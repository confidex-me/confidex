use super::{
    Code, Control, Diagnostic, Error, ErrorKind, Format, Limits, Location, Memory, Options, Phase,
    Progress, Reservation, Source, Status,
};
use confidex_vault::{
    record::{EncodedContent, Mapping, Record, Value},
    resources,
};
use std::io::Write;

pub type Attributes = Mapping;

pub struct Item {
    pub source: Source,
    pub record: Record,
    pub source_attributes: Attributes,
    pub status: Status,
    pub diagnostics: Vec<Diagnostic>,
}
impl Drop for Item {
    fn drop(&mut self) {
        drop(Record {
            extra: std::mem::take(&mut self.source_attributes),
            entries: Vec::new(),
            tags: Vec::new(),
        });
    }
}

pub struct PlannedItem {
    pub source: Source,
    pub status: Status,
    pub diagnostics: Vec<Diagnostic>,
    content: EncodedContent,
    attributes: EncodedContent,
    _memory: Reservation,
}
impl PlannedItem {
    pub fn record_bytes(&self) -> &[u8] {
        &self.content.bytes
    }
    pub fn source_attributes_bytes(&self) -> &[u8] {
        &self.attributes.bytes
    }
    /// Decode one item at a time in the host's admitted working memory.
    pub fn record(&self, memory_budget: usize) -> Result<Record, Error> {
        Record::decode_content(&self.content.bytes, memory_budget)
            .map(|r| r.record)
            .map_err(core_error)
    }
    pub fn source_attributes(&self, memory_budget: usize) -> Result<Attributes, Error> {
        decode_attributes(&self.attributes, memory_budget)
    }
    pub fn encoded_bytes(&self) -> usize {
        self.content.bytes.len() + self.attributes.bytes.len()
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Statistics {
    pub ready: usize,
    pub review: usize,
    pub blocked: usize,
    pub excluded: usize,
    pub encoded_bytes: usize,
}
pub struct Plan {
    pub format: Format,
    pub items: Vec<PlannedItem>,
    pub statistics: Statistics,
    pub container_status: Status,
    pub container_diagnostics: Vec<Diagnostic>,
    _memory: Reservation,
    memory: Memory,
    container: Option<EncodedContent>,
    _container_memory: Option<Reservation>,
}
impl Plan {
    pub fn container_attributes_bytes(&self) -> Option<&[u8]> {
        self.container
            .as_ref()
            .map(|content| content.bytes.as_slice())
    }
    pub fn memory(&self) -> &Memory {
        &self.memory
    }
    pub fn container_attributes(&self, memory_budget: usize) -> Result<Attributes, Error> {
        self.container
            .as_ref()
            .map(|content| decode_attributes(content, memory_budget))
            .unwrap_or_else(|| Ok(Mapping::new()))
    }
}
pub struct Context<'a> {
    pub options: &'a Options,
    pub limits: Limits,
    memory: Memory,
    control: Control<'a>,
    plan: Plan,
    _input: Reservation,
}
impl<'a> Context<'a> {
    pub fn new(
        format: Format,
        input_bytes: usize,
        options: &'a Options,
        limits: Limits,
        callback: &'a mut dyn FnMut(Progress) -> bool,
    ) -> Result<Self, Error> {
        let limits = limits.validate()?;
        if input_bytes > limits.input_bytes {
            return Err(ErrorKind::Limit.into());
        }
        if options.password.len() > limits.name_bytes
            || options.keyfile.len() > 1 << 20
            || options
                .source_instance
                .as_ref()
                .is_some_and(|s| s.len() > limits.name_bytes)
            || options.csv.as_ref().is_some_and(|m| {
                m.columns.len() > limits.fields
                    || !matches!(m.delimiter, b',' | b';' | b'\t' | b'|')
                    || m.columns.iter().any(|c| {
                        c.index >= limits.fields
                            || c.name.len() > limits.name_bytes
                            || c.target.len() > limits.name_bytes
                    })
            })
        {
            return Err(ErrorKind::InvalidOptions.into());
        }
        let memory = Memory::new(limits.memory_bytes);
        let input = memory.reserve(input_bytes)?;
        let headers = memory.reserve(
            limits.records * std::mem::size_of::<PlannedItem>()
                + limits.fields * std::mem::size_of::<Diagnostic>(),
        )?;
        let mut items = Vec::new();
        items
            .try_reserve_exact(limits.records)
            .map_err(|_| ErrorKind::Allocation)?;
        let mut container_diagnostics = Vec::new();
        container_diagnostics
            .try_reserve_exact(limits.fields)
            .map_err(|_| ErrorKind::Allocation)?;
        let mut result = Self {
            options,
            limits,
            memory: memory.clone(),
            control: Control::new(callback),
            plan: Plan {
                format,
                items,
                statistics: Statistics::default(),
                container_status: Status::Ready,
                container_diagnostics,
                _memory: headers,
                memory,
                container: None,
                _container_memory: None,
            },
            _input: input,
        };
        result.checkpoint(Phase::Inspect, 0, input_bytes)?;
        Ok(result)
    }
    pub fn memory(&self) -> &Memory {
        &self.memory
    }
    pub fn checkpoint(&mut self, phase: Phase, current: usize, total: usize) -> Result<(), Error> {
        self.control.checkpoint(phase, current, total)
    }
    /// Reserve before constructing owned values, including parser scratch space.
    pub fn reserve_work(&self, bytes: usize, nodes: usize) -> Result<Reservation, Error> {
        let size = bytes
            .checked_mul(2)
            .and_then(|v| nodes.checked_mul(256).and_then(|n| n.checked_add(v)))
            .and_then(|n| n.checked_add(2 << 20))
            .ok_or(ErrorKind::Limit)?;
        self.memory.reserve(size)
    }
    /// Container problems apply to the whole plan, including an empty selection.
    pub fn container_diagnostic(
        &mut self,
        status: Status,
        diagnostic: Diagnostic,
    ) -> Result<(), Error> {
        self.checkpoint(Phase::Validate, self.plan.items.len(), self.limits.records)?;
        if status == Status::Excluded {
            return Err(ErrorKind::InvalidOptions.into());
        }
        if !self.plan.container_diagnostics.contains(&diagnostic) {
            if self.plan.container_diagnostics.len() >= self.limits.fields {
                return Err(ErrorKind::Limit.into());
            }
            self.plan.container_diagnostics.push(diagnostic);
        }
        if status == Status::Blocked || self.plan.container_status == Status::Ready {
            self.plan.container_status = status;
        }
        Ok(())
    }
    /// Set shared source metadata once, independently of item selection.
    pub fn set_container_attributes(&mut self, attributes: Attributes) -> Result<(), Error> {
        let record = attribute_record(attributes);
        self.checkpoint(Phase::Validate, self.plan.items.len(), self.limits.records)?;
        if self.plan.container.is_some() {
            return Err(ErrorKind::InvalidOptions.into());
        }
        check_record(&record, self.limits, &mut 0)?;
        let content = record
            .encode_content(self.memory.available())
            .map_err(core_error)?;
        let total = self
            .plan
            .statistics
            .encoded_bytes
            .checked_add(content.bytes.len())
            .filter(|n| *n <= self.limits.plan_bytes)
            .ok_or(ErrorKind::Limit)?;
        let memory = self
            .memory
            .reserve(content.bytes.capacity() + content.value_sizes.capacity() * 8)?;
        self.plan.statistics.encoded_bytes = total;
        self.plan.container = Some(content);
        self.plan._container_memory = Some(memory);
        Ok(())
    }
    pub fn push(&mut self, mut item: Item) -> Result<(), Error> {
        let index = self.plan.items.len();
        let location = Location {
            item: Some(item.source.locator),
            ..Location::default()
        };
        self.checkpoint(Phase::Validate, index, self.limits.records)?;
        if index >= self.limits.records
            || item.record.entries.len() > self.limits.fields
            || item.diagnostics.len() > self.limits.fields
        {
            return Err(Error::from(ErrorKind::Limit).at(location));
        }
        if item.source.instance.is_none() {
            item.source.instance = self.options.source_instance.clone();
        }
        if [
            &item.source.instance,
            &item.source.account,
            &item.source.vault,
            &item.source.item,
        ]
        .into_iter()
        .flatten()
        .any(|s| s.len() > self.limits.name_bytes)
        {
            return Err(Error::from(ErrorKind::Limit).at(location));
        }
        if item.source.item.is_some() && !item.source.has_scoped_id() {
            item.diagnostics.push(Diagnostic {
                code: Code::MissingSourceScope,
                location,
            });
            if item.status == Status::Ready {
                item.status = Status::Review;
            }
        }
        if item.diagnostics.len() > self.limits.fields {
            return Err(Error::from(ErrorKind::Limit).at(location));
        }
        let mut nodes = 0;
        check_record(&item.record, self.limits, &mut nodes).map_err(|e| e.at(location))?;
        for (field, entry) in item.record.entries.iter().enumerate() {
            entry.validate_value().map_err(|_| {
                Error::from(ErrorKind::InvalidRecord).at(Location {
                    field: Some(field),
                    ..location
                })
            })?;
        }
        let attrs = attribute_record(std::mem::take(&mut item.source_attributes));
        check_record(&attrs, self.limits, &mut nodes).map_err(|e| e.at(location))?;
        let content = item
            .record
            .encode_content(self.memory.available())
            .map_err(core_error)?;
        // Use the same zlib profile and cap as the sealed core Record.
        let scratch = self.memory.reserve(1 << 20)?;
        compressed_limit(&content.bytes, || {
            self.checkpoint(Phase::Validate, index, self.limits.records)
        })
        .map_err(|e| e.at(location))?;
        drop(scratch);
        let content_memory = self
            .memory
            .reserve(content.bytes.capacity() + content.value_sizes.capacity() * 8)?;
        let attributes = attrs
            .encode_content(self.memory.available())
            .map_err(core_error)?;
        let bytes = content
            .bytes
            .len()
            .checked_add(attributes.bytes.len())
            .ok_or(ErrorKind::Limit)?;
        let total = self
            .plan
            .statistics
            .encoded_bytes
            .checked_add(bytes)
            .ok_or(ErrorKind::Limit)?;
        if total > self.limits.plan_bytes {
            return Err(Error::from(ErrorKind::Limit).at(location));
        }
        let metadata_bytes = [
            &item.source.instance,
            &item.source.account,
            &item.source.vault,
            &item.source.item,
        ]
        .into_iter()
        .flatten()
        .map(|s| s.capacity())
        .sum::<usize>()
            + item.diagnostics.capacity() * std::mem::size_of::<Diagnostic>();
        let reservation = self.memory.reserve(
            content.bytes.capacity()
                + content.value_sizes.capacity() * 8
                + attributes.bytes.capacity()
                + attributes.value_sizes.capacity() * 8
                + metadata_bytes,
        )?;
        drop(content_memory);
        self.plan.items.push(PlannedItem {
            source: std::mem::take(&mut item.source),
            status: item.status,
            diagnostics: std::mem::take(&mut item.diagnostics),
            content,
            attributes,
            _memory: reservation,
        });
        let stats = &mut self.plan.statistics;
        stats.encoded_bytes = total;
        match item.status {
            Status::Ready => stats.ready += 1,
            Status::Review => stats.review += 1,
            Status::Blocked => stats.blocked += 1,
            Status::Excluded => stats.excluded += 1,
        }
        Ok(())
    }
    pub fn finish(mut self) -> Result<Plan, Error> {
        self.checkpoint(
            Phase::Validate,
            self.plan.items.len(),
            self.plan.items.len(),
        )?;
        Ok(self.plan)
    }
}
fn core_error(error: confidex_vault::record::Error) -> Error {
    match error {
        confidex_vault::record::Error::Limit => ErrorKind::Limit,
        confidex_vault::record::Error::Allocation => ErrorKind::Allocation,
        _ => ErrorKind::InvalidRecord,
    }
    .into()
}
fn check_record(record: &Record, limits: Limits, nodes: &mut usize) -> Result<(), Error> {
    record.validate_structure().map_err(core_error)?;
    for entry in &record.entries {
        if entry.name.len() > limits.name_bytes || entry.type_name.len() > limits.name_bytes {
            return Err(ErrorKind::Limit.into());
        }
        check_map(&entry.value, limits, 0, nodes)?;
        check_map(&entry.extra, limits, 0, nodes)?;
    }
    check_map(&record.extra, limits, 0, nodes)
}
fn check_map(map: &Mapping, limits: Limits, depth: usize, nodes: &mut usize) -> Result<(), Error> {
    for (key, value) in map {
        if key.len() > limits.name_bytes {
            return Err(ErrorKind::Limit.into());
        }
        check_value(value, limits, depth + 1, nodes)?;
    }
    Ok(())
}
fn check_value(
    value: &Value,
    limits: Limits,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), Error> {
    *nodes = nodes.checked_add(1).ok_or(ErrorKind::Limit)?;
    if *nodes > limits.nodes || depth > limits.depth {
        return Err(ErrorKind::Limit.into());
    }
    match value {
        Value::String(s) if s.as_bytes().len() > limits.string_bytes => {
            return Err(ErrorKind::Limit.into());
        }
        Value::Binary(b) | Value::Ext(_, b) if b.len() > limits.unpacked_bytes => {
            return Err(ErrorKind::Limit.into());
        }
        Value::Array(a) => {
            for v in a {
                check_value(v, limits, depth + 1, nodes)?;
            }
        }
        Value::Map(m) => {
            for (k, v) in m {
                check_value(k, limits, depth + 1, nodes)?;
                check_value(v, limits, depth + 1, nodes)?;
            }
        }
        _ => (),
    }
    Ok(())
}
fn compressed_limit(
    bytes: &[u8],
    mut checkpoint: impl FnMut() -> Result<(), Error>,
) -> Result<(), Error> {
    struct Count(usize);
    impl Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|n| *n <= resources::MAX_COMPRESSED)
                .ok_or(std::io::ErrorKind::FileTooLarge)?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut encoder = flate2::write::ZlibEncoder::new(Count(0), flate2::Compression::new(6));
    for chunk in bytes.chunks(65_536) {
        checkpoint()?;
        encoder.write_all(chunk).map_err(|_| ErrorKind::Limit)?;
    }
    encoder.finish().map_err(|_| ErrorKind::Limit)?;
    Ok(())
}

pub fn attribute_record(attributes: Attributes) -> Record {
    Record {
        entries: Vec::new(),
        tags: Vec::new(),
        extra: Mapping::from([(
            "attributes".into(),
            Value::Map(attributes.into_iter().map(|(k, v)| (k.into(), v)).collect()),
        )]),
    }
}
fn decode_attributes(content: &EncodedContent, memory_budget: usize) -> Result<Attributes, Error> {
    let mut record = Record::decode_content(&content.bytes, memory_budget)
        .map_err(core_error)?
        .record;
    let Some(Value::Map(values)) = record.extra.remove("attributes") else {
        return Err(ErrorKind::InvalidRecord.into());
    };
    Ok(values
        .into_iter()
        .map(|(k, v)| {
            let Value::String(key) = k else {
                unreachable!("encoded attribute key");
            };
            (key.into_str().expect("encoded attribute key"), v)
        })
        .collect())
}

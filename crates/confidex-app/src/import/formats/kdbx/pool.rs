//! Keep binary bytes and source references together, including source history.
use super::{
    super::keepass_xml::{
        self, binary,
        document::{Document, Pool as XmlPool, xml_error},
        entry::flag,
        xml::Node,
    },
    protected::Values,
};
use crate::import::{Context, Error, ErrorKind, Reservation};
use keepass::{bounded::Raw, config::DatabaseVersion};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

pub(super) struct Data {
    pub bytes: Zeroizing<Vec<u8>>,
    pub protected: bool,
    pub memory: Reservation,
}

pub(super) struct Pool<'a> {
    raw: &'a Raw,
    values: &'a Values,
    xml: BTreeMap<&'a str, (&'a XmlPool, bool)>,
    used: Vec<bool>,
    unpacked: usize,
    _memory: Reservation,
}

pub(super) fn decode(node: &Node, compressed: bool, context: &Context<'_>) -> Result<Data, Error> {
    let text = node.leaf().map_err(|e| xml_error(e, node.span.start))?;
    let sizes = binary::sizes(text, compressed, context.limits.unpacked_bytes)
        .map_err(|e| xml_error(e, node.span.start))?;
    let memory = context
        .memory()
        .reserve(sizes.working().map_err(|e| xml_error(e, node.span.start))?)?;
    let bytes = binary::decode(text, compressed, context.limits.unpacked_bytes)
        .map_err(|e| xml_error(e, node.span.start))?;
    Ok(Data {
        bytes,
        protected: flag(node.attribute("ProtectInMemory"))?,
        memory,
    })
}

fn xml_data(
    member: &XmlPool,
    raw: &Raw,
    values: &Values,
    context: &mut Context<'_>,
) -> Result<Data, Error> {
    let fragment = values.fragment(raw.xml(), member.span.clone(), context)?;
    let _work = context.reserve_work(fragment.bytes.len(), member.nodes)?;
    let node = keepass_xml::load(&fragment.bytes, member.span.start, context)?;
    decode(&node, flag(node.attribute("Compressed"))?, context)
}

fn copy(bytes: &[u8], protected: bool, context: &Context<'_>) -> Result<Data, Error> {
    let memory = context.memory().reserve(bytes.len())?;
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(bytes.len())
        .map_err(|_| ErrorKind::Allocation)?;
    output.extend_from_slice(bytes);
    Ok(Data {
        bytes: output,
        protected,
        memory,
    })
}

impl<'a> Pool<'a> {
    pub fn new(
        raw: &'a Raw,
        values: &'a Values,
        doc: &'a Document,
        context: &mut Context<'_>,
    ) -> Result<Self, Error> {
        let memory = context.memory().reserve(
            raw.binary_count()
                .checked_add(doc.pools.len())
                .and_then(|n| n.checked_mul(256))
                .ok_or(ErrorKind::Limit)?,
        )?;
        let mut result = Self {
            raw,
            values,
            xml: BTreeMap::new(),
            used: vec![false; raw.binary_count()],
            unpacked: 0,
            _memory: memory,
        };
        if matches!(raw.version(), DatabaseVersion::KDB4(_)) && !doc.pools.is_empty() {
            return Err(ErrorKind::UnsupportedEncoding.into());
        }
        for index in 0..raw.binary_count() {
            result.count(
                raw.binary(index).ok_or(ErrorKind::Malformed)?.bytes.len(),
                context,
            )?;
        }
        for member in &doc.pools {
            let data = xml_data(member, raw, values, context)?;
            result.count(data.bytes.len(), context)?;
            result.xml.insert(member.id.as_str(), (member, false));
        }
        Ok(result)
    }

    fn count(&mut self, bytes: usize, context: &Context<'_>) -> Result<(), Error> {
        self.unpacked = self
            .unpacked
            .checked_add(bytes)
            .filter(|n| *n <= context.limits.unpacked_bytes)
            .ok_or(ErrorKind::Limit)?;
        Ok(())
    }

    pub fn read(
        &mut self,
        reference: &str,
        context: &mut Context<'_>,
    ) -> Result<Option<Data>, Error> {
        let repeated;
        let data = if matches!(self.raw.version(), DatabaseVersion::KDB4(_)) {
            let Some(index) = reference.parse::<usize>().ok() else {
                return Ok(None);
            };
            let Some(binary) = self.raw.binary(index) else {
                return Ok(None);
            };
            repeated = self.used[index];
            self.used[index] = true;
            copy(binary.bytes, binary.protected, context)?
        } else {
            let Some((member, used)) = self.xml.get_mut(reference) else {
                return Ok(None);
            };
            repeated = *used;
            *used = true;
            xml_data(member, self.raw, self.values, context)?
        };
        if repeated {
            self.count(data.bytes.len(), context)?;
        }
        Ok(Some(data))
    }

    pub fn inline(&mut self, node: &Node, context: &Context<'_>) -> Result<Data, Error> {
        let data = decode(node, false, context)?;
        self.count(data.bytes.len(), context)?;
        Ok(data)
    }

    pub fn orphan(&mut self, index: usize, context: &Context<'_>) -> Result<Option<Data>, Error> {
        if self.used[index] {
            return Ok(None);
        }
        let binary = self.raw.binary(index).ok_or(ErrorKind::Malformed)?;
        copy(binary.bytes, binary.protected, context).map(Some)
    }

    pub fn len(&self) -> usize {
        self.used.len()
    }
}

pub(super) fn references<'a>(node: &'a Node, output: &mut std::collections::BTreeSet<&'a str>) {
    for child in &node.children {
        match (node.name.as_str(), child.name.as_str()) {
            ("Entry", "Binary" | "History") | ("History", "Entry") => {
                references(child, output);
            }
            ("Binary", "Value") => {
                if let Some(reference) = child.attribute("Ref") {
                    output.insert(reference);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::{Format, Limits, Options};
    use std::collections::BTreeSet;

    #[test]
    fn references_follow_entry_history_and_leave_plugin_data_opaque() {
        let source = br#"<Entry>
            <Binary><Value Ref="current"/></Binary>
            <Plugin><Binary><Value Ref="plugin"/></Binary></Plugin>
            <History><Entry>
                <Binary><Value Ref="history"/></Binary>
                <Plugin><Binary><Value Ref="history-plugin"/></Binary></Plugin>
                <History><Entry><Binary><Value Ref="older"/></Binary></Entry></History>
            </Entry><Plugin><Entry><Binary><Value Ref="plugin-entry"/></Binary></Entry></Plugin></History>
        </Entry>"#;
        let options = Options::default();
        let mut check = |_| true;
        let mut context = Context::new(
            Format::Kdbx,
            source.len(),
            &options,
            Limits::default(),
            &mut check,
        )
        .unwrap();
        let node = keepass_xml::load(source, 0, &mut context).unwrap();
        let mut actual = BTreeSet::new();
        references(&node, &mut actual);
        assert_eq!(actual, BTreeSet::from(["current", "history", "older"]));
    }
}

//! Validate the whole document, then borrow items without a whole-file DOM.
use super::{Context, Error, ErrorKind, Limits, Phase, Reservation};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Value, value::RawValue};
use std::{
    collections::BTreeSet,
    fmt,
    ops::{Deref, DerefMut},
};
use zeroize::{Zeroize, Zeroizing};

pub struct Document<'a> {
    raw: &'a RawValue,
    _memory: Reservation,
}
pub struct Object<'a> {
    fields: Vec<(Zeroizing<String>, &'a RawValue)>,
    _memory: Reservation,
}
pub struct Owned {
    value: Value,
    _memory: Reservation,
}
impl Deref for Owned {
    type Target = Value;
    fn deref(&self) -> &Value {
        &self.value
    }
}
impl DerefMut for Owned {
    fn deref_mut(&mut self) -> &mut Value {
        &mut self.value
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        wipe(&mut self.value);
    }
}
fn wipe(value: &mut Value) {
    match std::mem::take(value) {
        Value::String(mut s) => s.zeroize(),
        Value::Array(mut a) => {
            for v in &mut a {
                wipe(v);
            }
        }
        Value::Object(m) => {
            for (mut k, mut v) in m {
                k.zeroize();
                wipe(&mut v);
            }
        }
        _ => (),
    }
}
impl<'a> Document<'a> {
    pub fn parse(input: &'a [u8], context: &mut Context<'_>) -> Result<Self, Error> {
        let input = input.strip_prefix(b"\xef\xbb\xbf").unwrap_or(input);
        let stats = scan(input, context)?;
        let memory = context.memory().reserve(
            input
                .len()
                .checked_mul(2)
                .and_then(|n| stats.checked_mul(32).and_then(|s| n.checked_add(s)))
                .ok_or(ErrorKind::Limit)?,
        )?;
        let mut check = Check {
            context,
            nodes: 0,
            error: None,
        };
        let mut deserializer = serde_json::Deserializer::from_slice(input);
        let result = Seed {
            check: &mut check,
            depth: 0,
        }
        .deserialize(&mut deserializer)
        .and_then(|()| deserializer.end());
        if result.is_err() {
            return Err(check.error.unwrap_or(ErrorKind::Malformed).into());
        }
        let raw = serde_json::from_slice(input).map_err(|_| ErrorKind::Malformed)?;
        Ok(Self {
            raw,
            _memory: memory,
        })
    }
    pub fn raw(&self) -> &'a RawValue {
        self.raw
    }
}
impl<'a> Object<'a> {
    pub fn get(&self, name: &str) -> Option<&'a RawValue> {
        self.fields
            .iter()
            .find(|(key, _)| key.as_str() == name)
            .map(|(_, value)| *value)
    }
    pub fn iter(&self) -> impl Iterator<Item = (&str, &'a RawValue)> {
        self.fields.iter().map(|(k, v)| (k.as_str(), *v))
    }
}
pub fn object<'a>(raw: &'a RawValue, context: &Context<'_>) -> Result<Object<'a>, Error> {
    let memory = context
        .memory()
        .reserve(context.limits.fields * (context.limits.name_bytes + 64))?;
    struct Fields<'a> {
        limits: Limits,
        marker: std::marker::PhantomData<&'a ()>,
    }
    impl<'de> Visitor<'de> for Fields<'de> {
        type Value = Vec<(Zeroizing<String>, &'de RawValue)>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("an object")
        }
        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut fields = Vec::new();
            fields
                .try_reserve_exact(self.limits.fields)
                .map_err(|_| serde::de::Error::custom("allocation"))?;
            while let Some(key) = map.next_key::<String>()? {
                let key = Zeroizing::new(key);
                if key.len() > self.limits.name_bytes || fields.len() >= self.limits.fields {
                    return Err(serde::de::Error::custom("limit"));
                }
                fields.push((key, map.next_value()?));
            }
            Ok(fields)
        }
    }
    let mut deserializer = serde_json::Deserializer::from_str(raw.get());
    let fields = serde::Deserializer::deserialize_map(
        &mut deserializer,
        Fields {
            limits: context.limits,
            marker: std::marker::PhantomData,
        },
    )
    .map_err(|_| ErrorKind::Malformed)?;
    Ok(Object {
        fields,
        _memory: memory,
    })
}
/// Use only slices from a validated Document. The guard wipes owned strings.
pub fn owned(raw: &RawValue, context: &mut Context<'_>) -> Result<Owned, Error> {
    let nodes = scan(raw.get().as_bytes(), context)?;
    let memory = context.reserve_work(raw.get().len(), nodes)?;
    let value = serde_json::from_str(raw.get()).map_err(|_| ErrorKind::Malformed)?;
    Ok(Owned {
        value,
        _memory: memory,
    })
}
pub fn array(raw: &RawValue) -> Result<Array<'_>, Error> {
    let s = raw.get().trim();
    if !s.starts_with('[') || !s.ends_with(']') {
        return Err(ErrorKind::Malformed.into());
    }
    Ok(Array {
        remaining: &s[1..s.len() - 1],
        first: true,
        failed: false,
    })
}
pub struct Array<'a> {
    remaining: &'a str,
    first: bool,
    failed: bool,
}
impl<'a> Iterator for Array<'a> {
    type Item = Result<&'a RawValue, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        self.remaining = self.remaining.trim_start();
        if self.remaining.is_empty() {
            return None;
        }
        if !self.first {
            let Some(rest) = self.remaining.strip_prefix(',') else {
                self.failed = true;
                return Some(Err(ErrorKind::Malformed.into()));
            };
            self.remaining = rest.trim_start();
        }
        self.first = false;
        let mut stream =
            serde_json::Deserializer::from_str(self.remaining).into_iter::<&'a RawValue>();
        match stream.next() {
            Some(Ok(raw)) => {
                self.remaining = &self.remaining[stream.byte_offset()..];
                Some(Ok(raw))
            }
            _ => {
                self.failed = true;
                Some(Err(ErrorKind::Malformed.into()))
            }
        }
    }
}
fn scan(input: &[u8], context: &mut Context<'_>) -> Result<usize, Error> {
    if input.len() > context.limits.input_bytes {
        return Err(ErrorKind::Limit.into());
    }
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    let mut start = 0;
    let mut nodes = 1usize;
    for (index, &byte) in input.iter().enumerate() {
        if index.is_multiple_of(65_536) {
            context.checkpoint(Phase::Read, index, input.len())?;
        }
        if quoted {
            if index - start > context.limits.string_bytes {
                return Err(ErrorKind::Limit.into());
            }
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => {
                    quoted = true;
                    start = index + 1;
                }
                b'{' | b'[' => {
                    depth += 1;
                    if depth > context.limits.depth {
                        return Err(ErrorKind::Limit.into());
                    }
                }
                b'}' | b']' => {
                    depth = depth.checked_sub(1).ok_or(ErrorKind::Malformed)?;
                }
                b':' | b',' => {
                    nodes += 1;
                    if nodes > context.limits.nodes {
                        return Err(ErrorKind::Limit.into());
                    }
                }
                _ => (),
            }
        }
    }
    if quoted || depth != 0 {
        return Err(ErrorKind::Malformed.into());
    }
    Ok(nodes)
}
struct Keys(BTreeSet<String>);
impl Drop for Keys {
    fn drop(&mut self) {
        for mut key in std::mem::take(&mut self.0) {
            key.zeroize();
        }
    }
}
struct Check<'a, 'b> {
    context: &'a mut Context<'b>,
    nodes: usize,
    error: Option<ErrorKind>,
}
struct Seed<'a, 'b, 'c> {
    check: &'a mut Check<'b, 'c>,
    depth: usize,
}
impl<'de> DeserializeSeed<'de> for Seed<'_, '_, '_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        self.check.nodes += 1;
        if self.depth > self.check.context.limits.depth
            || self.check.nodes > self.check.context.limits.nodes
        {
            self.check.error = Some(ErrorKind::Limit);
            return Err(serde::de::Error::custom("limit"));
        }
        if self.check.nodes.is_multiple_of(1024)
            && self
                .check
                .context
                .checkpoint(
                    Phase::Read,
                    self.check.nodes,
                    self.check.context.limits.nodes,
                )
                .is_err()
        {
            self.check.error = Some(ErrorKind::Canceled);
            return Err(serde::de::Error::custom("canceled"));
        }
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_, '_, '_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("JSON")
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<(), E> {
        if value.len() > self.check.context.limits.string_bytes {
            self.check.error = Some(ErrorKind::Limit);
            return Err(E::custom("limit"));
        }
        Ok(())
    }
    fn visit_seq<M: SeqAccess<'de>>(self, mut seq: M) -> Result<(), M::Error> {
        while seq
            .next_element_seed(Seed {
                check: self.check,
                depth: self.depth + 1,
            })?
            .is_some()
        {}
        Ok(())
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<(), M::Error> {
        let mut keys = Keys(BTreeSet::new());
        while let Some(key) = map.next_key::<String>()? {
            let key = Zeroizing::new(key);
            if key.len() > self.check.context.limits.name_bytes
                || keys.0.len() >= self.check.context.limits.fields
            {
                self.check.error = Some(ErrorKind::Limit);
                return Err(serde::de::Error::custom("limit"));
            }
            if keys.0.contains(key.as_str()) {
                self.check.error = Some(ErrorKind::DuplicateKey);
                return Err(serde::de::Error::custom("duplicate"));
            }
            keys.0.insert(key.to_string());
            map.next_value_seed(Seed {
                check: self.check,
                depth: self.depth + 1,
            })?;
        }
        Ok(())
    }
}

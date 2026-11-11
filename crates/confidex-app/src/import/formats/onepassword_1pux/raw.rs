use crate::import::{Context, Error, ErrorKind, json};
use confidex_vault::record::{Mapping, Value};
use serde_json::value::RawValue;
use zeroize::Zeroizing;

// Preserve numeric literals while removing whitespace outside JSON strings.
pub(super) fn compact(raw: &RawValue) -> Zeroizing<String> {
    let mut output = Zeroizing::new(String::with_capacity(raw.get().len()));
    let (mut quoted, mut escaped) = (false, false);
    for c in raw.get().chars() {
        if quoted {
            output.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                quoted = false;
            }
        } else if c == '"' {
            quoted = true;
            output.push(c);
        } else if !matches!(c, ' ' | '\t' | '\n' | '\r') {
            output.push(c);
        }
    }
    output
}
pub(super) fn without(
    raw: &RawValue,
    omitted: &str,
    context: &Context<'_>,
) -> Result<Value, Error> {
    let object = json::object(raw, context)?;
    Ok(Value::Map(
        object
            .iter()
            .filter(|(key, _)| *key != omitted)
            .map(|(key, fragment)| (key.into(), value(fragment)))
            .collect(),
    ))
}
pub(super) fn text(raw: &RawValue) -> Result<Zeroizing<String>, Error> {
    serde_json::from_str::<String>(raw.get())
        .map(Zeroizing::new)
        .map_err(|_| ErrorKind::Malformed.into())
}
pub(super) fn required<'a>(object: &json::Object<'a>, key: &str) -> Result<&'a RawValue, Error> {
    object.get(key).ok_or_else(|| ErrorKind::Malformed.into())
}
pub(super) fn id(
    object: &json::Object<'_>,
    key: &str,
    context: &Context<'_>,
) -> Result<Zeroizing<String>, Error> {
    let value = text(required(object, key)?)?;
    if value.trim().is_empty() || value.len() > context.limits.name_bytes {
        return Err(ErrorKind::Malformed.into());
    }
    Ok(value)
}
pub(super) fn value(raw: &RawValue) -> Value {
    let mut text = compact(raw);
    std::mem::take(&mut *text).into()
}
pub(super) fn snapshot(raw: &RawValue) -> Mapping {
    Mapping::from([("item".into(), value(raw))])
}
pub(super) fn original(path: &str, raw: &RawValue) -> confidex_vault::record::Entry {
    let encoded_path = Zeroizing::new(serde_json::to_string(path).unwrap());
    let data = compact(raw);
    let mut text = Zeroizing::new(String::with_capacity(encoded_path.len() + data.len() + 20));
    text.push_str("{\"path\":");
    text.push_str(&encoded_path);
    text.push_str(",\"data\":");
    text.push_str(&data);
    text.push('}');
    confidex_vault::record::Entry {
        name: "Original data".into(),
        type_name: "secure-note/v1".into(),
        value: Mapping::from([("text".into(), Value::from(std::mem::take(&mut *text)))]),
        extra: Mapping::from([("confidex.import.original".into(), path.into())]),
    }
}

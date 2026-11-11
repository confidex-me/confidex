use confidex_vault::record::{Entry, Mapping, Value};
use serde_json::Value as Json;

// Linked, malformed and future fields require protected source retention.
pub(super) fn custom(input: &Json) -> Option<Entry> {
    let object = input.as_object()?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "name" | "value" | "type" | "linkedId"))
        || object.get("linkedId").is_some_and(|value| !value.is_null())
    {
        return None;
    }
    let name = object.get("name")?.as_str()?;
    let text = object.get("value")?.as_str()?;
    let kind = object.get("type")?.as_u64()?;
    let (type_name, key) = match kind {
        0 => ("text/v1", "text"),
        1 => ("secret/v1", "secret"),
        2 if matches!(text, "true" | "false") => ("text/v1", "text"),
        _ => return None,
    };
    let mut source = vec![("type".into(), kind.into())];
    if object.contains_key("linkedId") {
        source.push(("linkedId".into(), Value::Nil));
    }
    let mut entry = Entry {
        name: name.into(),
        type_name: type_name.into(),
        value: Mapping::from([(key.into(), text.into())]),
        extra: Mapping::from([("confidex.import.field".into(), Value::Map(source))]),
    };
    if kind == 1 {
        entry.extra.insert(
            "metadata".into(),
            Value::Map(vec![("protected".into(), true.into())]),
        );
    }
    Some(entry)
}

type PersonalSlots = (&'static str, &'static [(&'static str, &'static str, bool)]);
pub(super) fn personal_slots(kind: u64) -> Option<PersonalSlots> {
    Some(match kind {
        3 => (
            "card",
            &[
                ("cardholderName", "Cardholder", false),
                ("brand", "Brand", false),
                ("number", "Card number", true),
                ("expMonth", "Expiry month", false),
                ("expYear", "Expiry year", false),
                ("code", "Security code", true),
            ],
        ),
        4 => (
            "identity",
            &[
                ("title", "Title", false),
                ("firstName", "First name", false),
                ("middleName", "Middle name", false),
                ("lastName", "Last name", false),
                ("address1", "Address 1", false),
                ("address2", "Address 2", false),
                ("address3", "Address 3", false),
                ("city", "City", false),
                ("state", "State", false),
                ("postalCode", "Postal code", false),
                ("country", "Country", false),
                ("company", "Company", false),
                ("email", "Email", false),
                ("phone", "Phone", false),
                ("ssn", "Social security number", true),
                ("username", "Username", false),
                ("passportNumber", "Passport number", true),
                ("licenseNumber", "License number", true),
            ],
        ),
        _ => return None,
    })
}
// Keep source components separate; null, malformed and unknown values stay for review.
pub(super) fn personal(kind: u64, input: &Json, entries: &mut Vec<Entry>) -> bool {
    let Some((group, slots)) = personal_slots(kind) else {
        return false;
    };
    let Some(object) = input.as_object() else {
        return false;
    };
    for &(slot, name, protected) in slots {
        if !object.get(slot).is_some_and(Json::is_string) {
            continue;
        }
        let Some(Json::String(text)) = object.get(slot) else {
            unreachable!();
        };
        let (type_name, key) = if protected {
            ("secret/v1", "secret")
        } else {
            ("text/v1", "text")
        };
        let mut entry = Entry {
            name: name.into(),
            type_name: type_name.into(),
            value: Mapping::from([(key.into(), text.as_str().into())]),
            extra: Mapping::from([(
                "confidex.import.field".into(),
                Value::Map(vec![
                    ("group".into(), group.into()),
                    ("slot".into(), slot.into()),
                ]),
            )]),
        };
        if protected {
            entry.extra.insert(
                "metadata".into(),
                Value::Map(vec![("protected".into(), true.into())]),
            );
        }
        entries.push(entry);
    }
    object.iter().all(|(key, value)| {
        slots.iter().any(|(slot, _, _)| key == slot) && (value.is_null() || value.is_string())
    })
}

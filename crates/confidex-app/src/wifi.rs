//! Wi-Fi references address positions in one record revision, not persistent field IDs.
use crate::Field;

pub fn remap(fields: &mut [Field], positions: &[Option<usize>]) {
    for field in fields.iter_mut().filter(|f| f.type_name == "wifi-qr/v1") {
        for key in ["ssid", "password"] {
            if let Some(value) = field.values.get_mut(key)
                && let Ok(index) = value.parse::<usize>()
            {
                *value = positions
                    .get(index)
                    .copied()
                    .flatten()
                    .map(|index| index.to_string())
                    .unwrap_or_default();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fields, template};
    use confidex_vault::{
        record::{Entry, Mapping, Record, Value},
        resources::MAX_OPEN_MEMORY,
    };

    #[test]
    fn references_roundtrip_and_follow_reorder_without_copying_credentials() {
        let mut fields = template("wifi").unwrap();
        fields[0].name = "Same".into();
        fields[1].name = "Same".into();
        fields[0].values.insert("text".into(), "Guest; café".into());
        fields[1]
            .values
            .insert("password".into(), "public-password".into());
        let mut record = Record::default();
        fields::apply(&mut record, &fields).unwrap();
        record.entries[2]
            .value
            .insert("future".into(), Value::Binary(vec![1, 2]));
        for entry in &record.entries {
            entry.validate_value().unwrap();
        }
        let wire = record.encode_content(MAX_OPEN_MEMORY).unwrap();
        let mut record = Record::decode_content(&wire.bytes, MAX_OPEN_MEMORY)
            .unwrap()
            .record;
        let mut fields = fields::read(&record).unwrap();
        fields.reverse();
        remap(&mut fields, &[Some(2), Some(1), Some(0)]);
        fields::apply(&mut record, &fields).unwrap();
        assert_eq!(record.entries[0].value["ssid"].as_str(), Some("2"));
        assert_eq!(record.entries[0].value["password"].as_str(), Some("1"));
        assert_eq!(record.entries[0].value["future"], Value::Binary(vec![1, 2]));
        assert!(
            !record.entries[0]
                .value
                .values()
                .any(|v| matches!(v.as_str(), Some("Guest; café" | "public-password")))
        );
        let mut fields = fields::read(&record).unwrap();
        fields.remove(1);
        remap(&mut fields, &[Some(0), None, Some(1)]);
        let reopened = fields::read(&record).unwrap();
        assert_eq!(reopened[0].values["password"], "1");
        fields::apply(&mut record, &fields).unwrap();
        assert_eq!(record.entries[0].value["password"].as_str(), Some(""));
        assert_eq!(record.entries[0].value["ssid"].as_str(), Some("1"));
    }

    #[test]
    fn legacy_expansion_remaps_positions_and_invalid_schema_is_rejected() {
        let mut record = Record::default();
        record.entries.push(Entry {
            name: "Legacy".into(),
            type_name: "login/v1".into(),
            value: Mapping::from([
                ("username".into(), Value::from("user")),
                ("password".into(), Value::from("pw")),
            ]),
            extra: Mapping::new(),
        });
        let mut fields = template("wifi").unwrap();
        fields[2].values.insert("ssid".into(), "2".into());
        fields[2].values.insert("password".into(), "3".into());
        let mut extra = Record::default();
        fields::apply(&mut extra, &fields).unwrap();
        record.entries.push(extra.entries.remove(2));
        record.entries.append(&mut extra.entries);
        let fields = fields::read(&record).unwrap();
        assert_eq!(fields[3].values["ssid"], "4");
        assert_eq!(fields[3].values["password"], "5");
        record.entries[1]
            .value
            .insert("auth".into(), Value::from("Enterprise"));
        assert!(record.entries[1].validate_value().is_err());
        record.entries[1]
            .value
            .insert("auth".into(), Value::from("WPA"));
        record.entries[1]
            .value
            .insert("ssid".into(), Value::from("not-a-position"));
        assert!(record.entries[1].validate_value().is_err());
    }
}

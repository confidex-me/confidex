use confidex_app::Draft;

/// Borrow usernames from supported login representations. The session UI only
/// needs previews, so it never serializes passwords or whole drafts.
pub fn usernames(draft: &Draft) -> impl Iterator<Item = &str> {
    let text = |kind: &str, key: &str| {
        let mut fields = draft.fields.iter().filter(|field| field.type_name == kind);
        let first = fields.next()?.values.get(key)?;
        fields.next().is_none().then_some(first.as_str())
    };
    let separate = text("username/v1", "username").filter(|_| {
        text("password/v1", "password").is_some_and(|value| !value.is_empty())
            && text("url/v1", "url").is_some_and(|value| !value.is_empty())
    });
    draft
        .fields
        .iter()
        .filter(|field| field.type_name == "login/v1")
        .filter_map(|field| {
            let password = field.values.get("password")?;
            let url = field.values.get("url")?;
            if password.is_empty() || url.is_empty() {
                return None;
            }
            Some(field.values.get("username").map_or("", String::as_str))
        })
        .chain(separate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use confidex_app::field;

    #[test]
    fn previews_distinguish_compound_fields_and_skip_ambiguous_separate_fields() {
        let mut draft = Draft {
            record: [0; 16],
            revision: None,
            title: "fixture".into(),
            fields: Vec::new(),
            tags: Vec::new(),
            sections: None,
        };
        for (kind, key, value) in [
            ("username/v1", "username", "separate"),
            ("password/v1", "password", "fixture-password"),
            ("url/v1", "url", "https://fixture.test"),
        ] {
            let mut field = field(kind).unwrap();
            field.values.insert(key.into(), value.into());
            draft.fields.push(field);
        }
        assert_eq!(usernames(&draft).collect::<Vec<_>>(), ["separate"]);
        for name in ["one", "two"] {
            let mut compound = draft.fields[0].clone();
            compound.type_name = "login/v1".into();
            compound.values.insert("username".into(), name.into());
            compound
                .values
                .insert("password".into(), "fixture-password".into());
            compound
                .values
                .insert("url".into(), "https://fixture.test".into());
            draft.fields.push(compound);
        }
        assert_eq!(
            usernames(&draft).collect::<Vec<_>>(),
            ["one", "two", "separate"]
        );
        draft.fields.push(field("username/v1").unwrap());
        assert_eq!(usernames(&draft).collect::<Vec<_>>(), ["one", "two"]);
    }
}

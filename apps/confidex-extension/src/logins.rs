use crate::protocol::Login;
use confidex_app::Draft;

pub const LOGIN_PAGE_SIZE: usize = 128;

/// Borrow usernames from supported login representations. The session UI only
/// needs previews, so it never serializes passwords or whole drafts.
fn usernames(draft: &Draft) -> impl Iterator<Item = &str> {
    let text = |kind: &str, key: &str| {
        let mut fields = draft
            .fields
            .iter()
            .filter(|field| field.type_name == kind && field.source_key.is_none());
        let first = fields.next()?.values.get(key)?;
        fields.next().is_none().then_some(first.as_str())
    };
    let separate = text("username/v1", "username").filter(|_| {
        text("password/v1", "password").is_some_and(|value| !value.is_empty())
            && text("url/v1", "url").is_some_and(|value| !value.is_empty())
    });
    let projected = draft
        .fields
        .chunk_by(|left, right| left.source == right.source)
        .filter_map(|group| {
            // Engine::Open projects compound entries using a shared source index.
            let [username, password, url] = group else {
                return None;
            };
            if username.source.is_none()
                || username.source_key.as_deref() != Some("username")
                || password.source_key.as_deref() != Some("password")
                || url.source_key.as_deref() != Some("url")
                || password.values.get("password")?.is_empty()
                || url.values.get("url")?.is_empty()
            {
                return None;
            }
            Some(username.values.get("username").map_or("", String::as_str))
        });
    let compound = draft
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
        });
    projected.chain(compound).chain(separate)
}

/// Return the offset of the first login to carry over to the next page.
pub fn append_previews(draft: &Draft, offset: usize, page: &mut Vec<Login>) -> Option<usize> {
    for (index, username) in usernames(draft).enumerate().skip(offset) {
        if page.len() == LOGIN_PAGE_SIZE {
            return Some(index);
        }
        page.push(Login {
            title: draft.title.chars().take(128).collect(),
            username: username.chars().take(128).collect(),
        });
    }
    None
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

    #[test]
    fn projected_logins_resume_within_a_record_at_the_page_boundary() {
        let mut draft = Draft {
            record: [2; 16],
            revision: Some([3; 32]),
            title: "Compound entries".into(),
            fields: Vec::new(),
            tags: Vec::new(),
            sections: None,
        };
        for (source, name) in ["first", "second", "third"].into_iter().enumerate() {
            for (kind, key, value) in [
                ("username/v1", "username", name),
                ("password/v1", "password", "fixture-password"),
                ("url/v1", "url", "https://fixture.test"),
            ] {
                let mut field = field(kind).unwrap();
                field.source = Some(source);
                field.source_key = Some(key.into());
                field.values.insert(key.into(), value.into());
                draft.fields.push(field);
            }
        }
        let mut first_page: Vec<_> = (0..127)
            .map(|index| Login {
                title: "Other record".into(),
                username: format!("fixture-{index}"),
            })
            .collect();
        let offset = append_previews(&draft, 0, &mut first_page).unwrap();
        assert_eq!(first_page.len(), 128);
        assert_eq!(first_page.last().unwrap().username, "first");
        assert_eq!(offset, 1);

        let mut next_page = Vec::new();
        assert_eq!(append_previews(&draft, offset, &mut next_page), None);
        assert_eq!(
            next_page
                .iter()
                .map(|login| login.username.as_str())
                .collect::<Vec<_>>(),
            ["second", "third"],
        );
    }
}

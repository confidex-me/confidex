use super::*;

fn entry(kind: &str, values: &[(&str, &str)]) -> Entry {
    Entry {
        name: kind.into(),
        type_name: kind.into(),
        value: values
            .iter()
            .map(|(key, value)| ((*key).into(), Value::from(*value)))
            .collect(),
        extra: BTreeMap::new(),
    }
}

fn compound(username: &str) -> Entry {
    entry(
        "login/v1",
        &[
            ("username", username),
            ("password", "fixture-secret"),
            ("url", "https://example.test/path?q=keep"),
            ("vendor-setting", "keep"),
        ],
    )
}

#[test]
fn creates_a_standard_login_and_stores_only_the_https_origin() {
    let mut login = NewLogin {
        title: " Test ".into(),
        username: "user".into(),
        password: "fixture-secret".into(),
        url: "https://Bücher.example:8443/path?query#fragment".into(),
        notes: "First line\nSecond line".into(),
        tags: vec!["work".into(), "admin".into()],
    };
    let record = new_content(&login).unwrap();
    assert_eq!(title(&record).unwrap(), "Test");
    assert_eq!(
        record
            .entries
            .iter()
            .map(|entry| entry.type_name.as_str())
            .collect::<Vec<_>>(),
        ["username/v1", "password/v1", "url/v1", "note/v1"],
    );
    assert_eq!(
        text(&record.entries[2], "url"),
        Some("https://xn--bcher-kva.example:8443")
    );
    assert_eq!(text(&record.entries[3], "text"), Some(login.notes.as_str()));
    assert_eq!(record.tags, ["admin", "work"]);
    assert_eq!(pairs(&record).0.count(), 1);
    for invalid in [
        "http://example.test",
        "https://user:secret@example.test",
        "example.test/path",
    ] {
        login.url = invalid.into();
        assert!(matches!(new_content(&login), Err(Error::Input)));
    }
}

#[test]
fn compound_options_are_distinct_and_an_ambiguous_separate_pair_is_skipped() {
    let mut record = Record {
        entries: vec![
            compound("first"),
            compound("second"),
            entry("username/v1", &[("username", "separate")]),
            entry("password/v1", &[("password", "fixture-secret")]),
            entry("url/v1", &[("url", "https://example.test")]),
        ],
        tags: vec![],
        extra: BTreeMap::new(),
    };
    assert_eq!(
        pairs(&record)
            .0
            .map(|pair| pair.password)
            .collect::<Vec<_>>(),
        [0, 1, 3]
    );
    record.entries.push(entry("username/v1", &[]));
    let (pairs, ambiguous) = pairs(&record);
    assert!(ambiguous);
    assert_eq!(pairs.map(|pair| pair.password).collect::<Vec<_>>(), [0, 1]);
}

#[test]
fn update_changes_only_the_selected_raw_keys() {
    let mut record = Record {
        entries: vec![
            compound("first"),
            compound("second"),
            entry("note/v1", &[("text", "keep")]),
        ],
        tags: vec!["important".into()],
        extra: BTreeMap::from([(TITLE_KEY.into(), Value::from("Title"))]),
    };
    sections::apply(
        &mut record,
        Some(&[sections::Section::new("Account", 0, 1)]),
        3,
    )
    .unwrap();
    record.entries[0]
        .extra
        .insert("vendor".into(), Value::from(true));
    let before = record.encode_content(MAX_OPEN_MEMORY).unwrap();
    let change = Change {
        username: Some("updated".into()),
        password: Some("replacement".into()),
        tags: None,
    };
    update_content(&mut record, 0, &change).unwrap();
    assert_eq!(text(&record.entries[0], "username"), Some("updated"));
    assert_eq!(text(&record.entries[0], "password"), Some("replacement"));
    assert!(matches!(
        update_content(&mut record, 2, &change),
        Err(Error::Input)
    ));
    update_content(
        &mut record,
        0,
        &Change {
            username: Some("first".into()),
            password: Some("fixture-secret".into()),
            tags: None,
        },
    )
    .unwrap();
    let after = record.encode_content(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(*before.bytes, *after.bytes);
}

#[test]
fn tags_can_be_replaced_without_touching_credentials_or_other_fields() {
    let mut record = Record {
        entries: vec![compound("fixture")],
        tags: vec!["original".into()],
        extra: BTreeMap::new(),
    };
    let mut change = Change {
        username: None,
        password: None,
        tags: Some(vec!["work".into(), "work".into()]),
    };
    assert!(matches!(
        update_content(&mut record, 0, &change),
        Err(Error::Input)
    ));
    assert_eq!(record.tags, ["original"]);
    change.tags = Some(vec!["work".into(), "admin".into()]);
    update_content(&mut record, 0, &change).unwrap();
    assert_eq!(record.tags, ["admin", "work"]);
    assert_eq!(text(&record.entries[0], "username"), Some("fixture"));
    assert_eq!(text(&record.entries[0], "password"), Some("fixture-secret"));
    assert_eq!(text(&record.entries[0], "vendor-setting"), Some("keep"));
    change.tags = Some(vec![]);
    update_content(&mut record, 0, &change).unwrap();
    assert!(record.tags.is_empty());
}

#[test]
fn previews_page_within_a_revision_and_serialize_no_secrets() {
    let record = Record {
        entries: (0..PAGE_SIZE + 2)
            .map(|index| compound(&format!("user-{index}")))
            .collect(),
        tags: vec![],
        extra: BTreeMap::new(),
    };
    let head = Head {
        record: [1; 16],
        revision: [2; 32],
    };
    let mut page = Page {
        rows: vec![],
        issues: Issues::default(),
        next: None,
    };
    let offset = append_previews(&record, &head, 0, &mut page).unwrap();
    assert_eq!(offset, PAGE_SIZE);
    assert_eq!(page.rows.last().unwrap().target.field, PAGE_SIZE - 1);
    page.rows.clear();
    assert_eq!(append_previews(&record, &head, offset, &mut page), None);
    assert_eq!(
        page.rows
            .iter()
            .map(|row| row.target.field)
            .collect::<Vec<_>>(),
        [PAGE_SIZE, PAGE_SIZE + 1]
    );
    let preview = serde_json::to_string(&page).unwrap();
    assert!(!preview.contains("fixture-secret"));
    assert!(!preview.contains("q=keep"));
}

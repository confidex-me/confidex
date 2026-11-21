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
    let mut change = Change::default();
    change.username = Some("updated".into());
    change.password = Some("replacement".into());
    update_content(&mut record, 0, &change).unwrap();
    assert_eq!(text(&record.entries[0], "username"), Some("updated"));
    assert_eq!(text(&record.entries[0], "password"), Some("replacement"));
    assert!(matches!(
        update_content(&mut record, 2, &change),
        Err(Error::Input)
    ));
    change.username = Some("first".into());
    change.password = Some("fixture-secret".into());
    update_content(&mut record, 0, &change).unwrap();
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
    let mut change = Change::default();
    change.tags = Some(vec!["work".into(), "work".into()]);
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
fn editor_reads_full_values_without_the_saved_password() {
    let mut login = compound(&"u".repeat(256));
    login
        .value
        .insert("vendor-password".into(), Value::from("vendor-secret"));
    let record = Record {
        entries: vec![login, entry("note/v1", &[("text", "Project notes")])],
        tags: vec!["work".into()],
        extra: BTreeMap::from([(TITLE_KEY.into(), Value::from(" Full title"))]),
    };
    let fields = editor_content(record, 0).unwrap();
    assert_eq!(fields.title, " Full title");
    assert_eq!(fields.username.as_deref(), Some("u".repeat(256).as_str()));
    assert_eq!(
        fields.url.as_deref(),
        Some("https://example.test/path?q=keep")
    );
    assert_eq!(fields.notes.as_deref(), Some("Project notes"));
    assert_eq!(fields.tags, ["work"]);
    let json = serde_json::to_string(&fields).unwrap();
    assert!(
        !json.contains("password")
            && !json.contains("fixture-secret")
            && !json.contains("vendor-secret")
    );
}

#[test]
fn edits_selected_website_and_title_and_only_an_unambiguous_note() {
    let mut record = Record {
        entries: vec![
            compound("first"),
            compound("second"),
            entry("secure-note/v1", &[("text", "private")]),
        ],
        tags: vec![],
        extra: BTreeMap::new(),
    };
    sections::apply(
        &mut record,
        Some(&[sections::Section::new("Login fields", 0, 2)]),
        3,
    )
    .unwrap();
    let original_sections = record.extra[sections::KEY].clone();
    let mut change = Change::default();
    change.title = Some(" Edited ".into());
    change.url = Some("https://new.example.test/path?ignored=1".into());
    change.notes = Some("New note".into());
    update_content(&mut record, 1, &change).unwrap();
    assert_eq!(title(&record).unwrap(), "Edited");
    assert_eq!(
        text(&record.entries[0], "url"),
        Some("https://example.test/path?q=keep")
    );
    assert_eq!(
        text(&record.entries[1], "url"),
        Some("https://new.example.test")
    );
    assert_eq!(text(&record.entries[1], "password"), Some("fixture-secret"));
    assert_eq!(text(&record.entries[2], "text"), Some("private"));
    assert_eq!(text(&record.entries[3], "text"), Some("New note"));
    assert_eq!(record.entries[3].name, "Notes");
    assert_eq!(record.extra[sections::KEY], original_sections);

    record
        .entries
        .push(entry("note/v1", &[("text", "Other note")]));
    assert!(matches!(
        update_content(&mut record, 1, &change),
        Err(Error::Input)
    ));
    assert_eq!(text(&record.entries[3], "text"), Some("New note"));
    assert_eq!(text(&record.entries[4], "text"), Some("Other note"));
    assert!(editor_content(record, 1).unwrap().notes.is_none());
}

#[test]
fn serialized_previews_omit_protected_separate_and_compound_usernames() {
    let protect = |mut entry: Entry| {
        entry.extra.insert(
            "metadata".into(),
            Value::Map(vec![(Value::from("protected"), Value::from(true))]),
        );
        entry
    };
    let record = Record {
        entries: vec![
            protect(entry(
                "username/v1",
                &[("username", "private-separate-user")],
            )),
            entry("password/v1", &[("password", "fixture-password")]),
            entry("url/v1", &[("url", "https://example.test")]),
            protect(compound("private-compound-user")),
            compound("public-compound-user"),
        ],
        tags: vec![],
        extra: BTreeMap::new(),
    };
    let mut page = Page {
        rows: vec![],
        next: None,
        issues: Issues::default(),
    };
    let head = Head {
        record: [1; 16],
        revision: [2; 32],
    };
    assert!(append_previews(&record, &head, 0, &mut page, None).is_none());
    let serialized = serde_json::to_string(&page).unwrap();
    assert!(!serialized.contains("private-separate-user"));
    assert!(!serialized.contains("private-compound-user"));
    assert!(serialized.contains("public-compound-user"));
    let rows = serde_json::from_str::<Page>(&serialized).unwrap().rows;
    assert_eq!(
        rows.iter()
            .map(|row| row.username.as_str())
            .collect::<Vec<_>>(),
        ["", "public-compound-user", ""],
    );
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
    let offset = append_previews(&record, &head, 0, &mut page, None).unwrap();
    assert_eq!(offset, PAGE_SIZE);
    assert_eq!(page.rows.last().unwrap().target.field, PAGE_SIZE - 1);
    page.rows.clear();
    assert_eq!(
        append_previews(&record, &head, offset, &mut page, None),
        None
    );
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

#[test]
fn autofill_matches_only_the_canonical_https_origin() {
    let mut entry = compound("first");
    entry.value.insert(
        "url".into(),
        Value::from("https://Bücher.example:443/login?private=1#form"),
    );
    let mut record = Record::default();
    record.entries.push(entry);
    let pair = login_pair(&record, 0).unwrap();
    assert_eq!(
        fill_values(&record, &pair, "https://xn--bcher-kva.example"),
        Some(("first", "fixture-secret"))
    );
    for origin in [
        "http://xn--bcher-kva.example",
        "https://xn--bcher-kva.example:444",
        "https://accounts.xn--bcher-kva.example",
        "https://xn--bcher-kva.example.attacker.test",
    ] {
        assert!(fill_values(&record, &pair, origin).is_none());
    }
}

use super::*;
use confidex_vault::record::Record;
use std::io::{Cursor, Read, Write};
use zeroize::{Zeroize, Zeroizing};

const LOCAL: &str = "LOCAL-EDIT-PASSWORD-PRIVATE";
const SOURCE: &str = "SOURCE-EDIT-PASSWORD-PRIVATE";

fn splice(input: &[u8], offset: usize, length: usize, value: &[u8]) -> Zeroizing<Vec<u8>> {
    assert!(offset + length <= input.len());
    let mut result = Zeroizing::new(Vec::with_capacity(input.len() + value.len()));
    result.extend_from_slice(&input[..offset]);
    result.extend_from_slice(value);
    result.extend_from_slice(&input[offset + length..]);
    result
}
pub(super) fn json_password(
    input: &[u8],
    format: import::Format,
    value: &str,
) -> Zeroizing<Vec<u8>> {
    let options = import::Options::default();
    let mut callback = |_| true;
    let mut context = import::Context::new(
        format,
        input.len(),
        &options,
        import::Limits::default(),
        &mut callback,
    )
    .unwrap();
    let document = import::json::Document::parse(input, &mut context).unwrap();
    let path: &[&str] = if format == import::Format::Onepassword1pux {
        &[
            "accounts",
            "0",
            "vaults",
            "0",
            "items",
            "0",
            "details",
            "loginFields",
            "1",
            "value",
        ]
    } else {
        &["items", "0", "login", "password"]
    };
    let mut raw = document.raw();
    for step in path {
        raw = if let Ok(index) = step.parse::<usize>() {
            import::json::array(raw)
                .unwrap()
                .nth(index)
                .unwrap()
                .unwrap()
        } else {
            import::json::object(raw, &context)
                .unwrap()
                .get(step)
                .unwrap()
        };
    }
    assert!(raw.get().starts_with('"') && raw.get().ends_with('"'));
    let offset = raw.get().as_ptr() as usize - input.as_ptr() as usize;
    let value = Zeroizing::new(serde_json::to_vec(value).unwrap());
    splice(input, offset, raw.get().len(), &value)
}
fn changed_input(case: &Case) -> Zeroizing<Vec<u8>> {
    match case.format {
        import::Format::BitwardenJson => json_password(case.input, case.format, SOURCE),
        import::Format::BitwardenZip | import::Format::Onepassword1pux => {
            let member = if case.format == import::Format::BitwardenZip {
                "data.json"
            } else {
                "export.data"
            };
            let mut archive = zip::ZipArchive::new(Cursor::new(case.input)).unwrap();
            let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
            let mut replaced = 0;
            for index in 0..archive.len() {
                let mut file = archive.by_index(index).unwrap();
                let name = file.name().unwrap().into_owned();
                if file.is_dir() {
                    writer
                        .add_directory(name, zip::write::SimpleFileOptions::default())
                        .unwrap();
                    continue;
                }
                let mut bytes = Zeroizing::new(Vec::new());
                file.read_to_end(&mut bytes).unwrap();
                if name == member {
                    bytes = json_password(&bytes, case.format, SOURCE);
                    replaced += 1;
                }
                writer
                    .start_file(
                        name,
                        zip::write::SimpleFileOptions::default()
                            .compression_method(zip::CompressionMethod::Stored),
                    )
                    .unwrap();
                writer.write_all(&bytes).unwrap();
            }
            assert_eq!(replaced, 1);
            Zeroizing::new(writer.finish().unwrap().into_inner())
        }
        import::Format::KeepassXml => {
            let text = std::str::from_utf8(case.input).unwrap();
            let key = text.find("<Key>Password</Key>").unwrap();
            let value = key + text[key..].find("<Value").unwrap();
            let start = value + text[value..].find('>').unwrap() + 1;
            let length = text[start..].find("</Value>").unwrap();
            splice(case.input, start, length, SOURCE.as_bytes())
        }
        import::Format::Csv => {
            let mut start = case.input.iter().position(|b| *b == b'\n').unwrap() + 1;
            for _ in 0..3 {
                let length = case.input[start..].iter().position(|b| *b == b',').unwrap();
                assert!(!case.input[start..start + length].contains(&b'"'));
                start += length + 1;
            }
            let length = case.input[start..].iter().position(|b| *b == b',').unwrap();
            assert!(!case.input[start..start + length].contains(&b'"'));
            splice(case.input, start, length, SOURCE.as_bytes())
        }
        import::Format::BitwardenEncryptedJson => {
            Zeroizing::new(include_bytes!("fixtures/encrypted/pbkdf2-legacy.json").to_vec())
        }
        import::Format::Kdbx => Zeroizing::new(
            match case.name {
                "kdbx-password" => include_bytes!("fixtures/kdbx/password.kdbx").as_slice(),
                "kdbx-keyfile" => include_bytes!("fixtures/kdbx/keyfile.kdbx").as_slice(),
                "kdbx-both" => include_bytes!("fixtures/kdbx/both.kdbx").as_slice(),
                "kdbx-empty-password" => {
                    include_bytes!("fixtures/kdbx/empty-password.kdbx").as_slice()
                }
                "kdbx-empty-password-keyfile" => {
                    include_bytes!("fixtures/kdbx/empty-password-keyfile.kdbx").as_slice()
                }
                _ => panic!("KDBX capture"),
            }
            .to_vec(),
        ),
    }
}
fn selection(count: usize, action: Action, reviewed: bool) -> Selection {
    Selection {
        container_reviewed: true,
        choices: (0..count)
            .map(|index| Choice {
                action: if index == 0 {
                    action.clone()
                } else {
                    Action::Skip
                },
                reviewed,
            })
            .collect(),
    }
}
async fn preview<S: Store>(
    engine: &mut Engine,
    store: &mut S,
    case: &Case,
    input: &[u8],
) -> confidex_app::import_apply::Review {
    let id = engine.begin_import().unwrap();
    engine
        .review_import(store, id, case.plan_from(input), &mut |_| true)
        .await
        .unwrap()
}

pub async fn run<S: Store>(store: &mut S, case: &Case, created: &Created) {
    let id = created.info.id;
    let mut engine = Engine::default();
    command(
        &mut engine,
        store,
        Command::Unlock {
            vault: id,
            password: PASSWORD.into(),
            key: created.key.clone(),
            remember: false,
        },
    )
    .await;
    let saved = store.vault(id).await.unwrap();
    let code = transfer_code::decode(&created.key).unwrap();
    let vault = lock::open(
        &saved.lock,
        PASSWORD.as_bytes(),
        &code.secret,
        kdf::REQUIRED_MEMORY,
    )
    .unwrap();
    let expected = case.plan();
    let mut target = None;
    for head in heads(store, id).await {
        let wire = store.object(id, head.revision).await.unwrap();
        let opened = envelope::open(
            &wire,
            vault.keys(),
            vault.anchor(),
            Some(&head.revision),
            MAX_OPEN_MEMORY,
        )
        .unwrap();
        if same_source(
            field(&opened.record.extra[ORIGIN], "source"),
            &expected.items[0].source,
        ) {
            assert!(target.is_none());
            target = Some((head, opened.record));
        }
    }
    let (original, mut expected_local) = target.unwrap();
    let original_wire = store.object(id, original.revision).await.unwrap();
    let Output::Draft(mut draft) = command(
        &mut engine,
        store,
        Command::Open {
            record: original.record,
        },
    )
    .await
    else {
        panic!("open")
    };
    if case.format == import::Format::Onepassword1pux {
        assert_eq!(
            draft.sections,
            Some(vec![confidex_app::sections::Section {
                source: Some(0),
                name: "Security".into(),
                start: 5,
                count: 5,
            }])
        );
        assert_eq!(
            expected_local.extra["confidex.sections"],
            Value::Map(vec![
                (
                    "groups".into(),
                    Value::Array(vec![Value::Map(vec![
                        ("count".into(), 5_u64.into()),
                        ("name".into(), "Security".into()),
                        ("start".into(), 5_u64.into()),
                    ])]),
                ),
                ("version".into(), 1_u64.into()),
            ]),
        );
    }
    let entry = expected_local
        .entries
        .iter()
        .position(|entry| entry.type_name == "password/v1")
        .unwrap();
    let password = draft
        .fields
        .iter_mut()
        .find(|field| field.type_name == "password/v1")
        .unwrap()
        .values
        .get_mut("password")
        .unwrap();
    password.zeroize();
    password.push_str(LOCAL);
    let mut retired = Record::default();
    retired.extra.insert(
        "password".into(),
        expected_local.entries[entry]
            .value
            .insert("password".into(), Value::from(LOCAL))
            .unwrap(),
    );
    assert!(matches!(
        command(&mut engine, store, Command::Save { draft, epoch: 10 }).await,
        Output::Saved(_)
    ));
    let local = store.head(id, original.record).await.unwrap().unwrap();
    assert_ne!(local.revision, original.revision);
    let local_wire = store.object(id, local.revision).await.unwrap();
    let opened = envelope::open(
        &local_wire,
        vault.keys(),
        vault.anchor(),
        Some(&local.revision),
        MAX_OPEN_MEMORY,
    )
    .unwrap();
    assert_eq!(opened.revision.header().parents, [original.revision]);
    assert_eq!(opened.revision.header().metadata.epoch, 10);
    assert_eq!(
        opened
            .record
            .encode_content(MAX_OPEN_MEMORY)
            .unwrap()
            .bytes
            .as_slice(),
        expected_local
            .encode_content(MAX_OPEN_MEMORY)
            .unwrap()
            .bytes
            .as_slice(),
        "{} local edit changed unrelated fields",
        case.name
    );
    assert!(search(&mut engine, store, LOCAL).await.is_empty());
    let before = store.snapshot(id).await.unwrap();
    let unchanged = preview(&mut engine, store, case, case.input).await;
    assert_eq!(unchanged.items[0].matching, Match::Conflict);
    let candidates = engine.import_candidates(unchanged.token, 0, 0).unwrap();
    assert_eq!(candidates.items.len(), 1);
    assert!(candidates.items[0].local_changed && !candidates.items[0].source_changed);
    assert_eq!(candidates.items[0].head, local);
    engine.cancel_import(unchanged.token).unwrap();
    same_snapshot(&before, &store.snapshot(id).await.unwrap());
    let input = changed_input(case);
    let changed = case.plan_from(&input);
    if case.format == import::Format::BitwardenEncryptedJson {
        let plain = &crate::cases::CASES[0];
        let plaintext = json_password(plain.input, plain.format, SOURCE);
        let reference = plain.plan_from(&plaintext);
        assert_eq!(changed.items.len(), reference.items.len());
        for (actual, expected) in changed.items.iter().zip(&reference.items) {
            assert_eq!(actual.record_bytes(), expected.record_bytes());
            assert_eq!(
                actual.source_attributes_bytes(),
                expected.source_attributes_bytes()
            );
            assert_eq!(
                (
                    &actual.source.instance,
                    &actual.source.account,
                    &actual.source.vault,
                    &actual.source.item,
                    actual.source.locator
                ),
                (
                    &expected.source.instance,
                    &expected.source.account,
                    &expected.source.vault,
                    &expected.source.item,
                    expected.source.locator
                ),
            );
            assert_eq!(actual.status, expected.status);
            assert_eq!(actual.diagnostics, expected.diagnostics);
        }
    }
    assert_eq!(
        changed.items[0]
            .record(MAX_OPEN_MEMORY)
            .unwrap()
            .entries
            .iter()
            .find(|entry| entry.type_name == "password/v1")
            .unwrap()
            .value["password"]
            .as_str(),
        Some(SOURCE)
    );
    let review = preview(&mut engine, store, case, &input).await;
    let weak = !expected.items[0].source.has_scoped_id();
    assert_eq!(
        review.items[0].matching,
        if weak { Match::New } else { Match::Conflict }
    );
    let candidates = engine.import_candidates(review.token, 0, 0).unwrap();
    if weak {
        assert!(candidates.items.is_empty());
    } else {
        assert_eq!(candidates.items.len(), 1);
        assert_eq!(candidates.items[0].head, local);
        assert!(candidates.items[0].source_changed && candidates.items[0].local_changed);
    }
    assert_eq!(
        engine
            .apply_import(
                store,
                review.token,
                &selection(case.total, Action::Update(local.clone()), false),
                5,
                &mut |_| true
            )
            .await,
        Err(Error::InvalidChoice)
    );
    same_snapshot(&before, &store.snapshot(id).await.unwrap());
    if weak {
        let review = preview(&mut engine, store, case, &input).await;
        assert_eq!(
            engine
                .apply_import(
                    store,
                    review.token,
                    &selection(case.total, Action::Update(local.clone()), true),
                    5,
                    &mut |_| true
                )
                .await,
            Err(Error::InvalidChoice)
        );
        same_snapshot(&before, &store.snapshot(id).await.unwrap());
    }
    let review = preview(&mut engine, store, case, &input).await;
    let all_skip = selection(case.total, Action::Skip, true);
    assert_eq!(
        engine
            .apply_import(store, review.token, &all_skip, 5, &mut |_| true)
            .await
            .unwrap()
            .skipped,
        case.total
    );
    same_snapshot(&before, &store.snapshot(id).await.unwrap());
    let review = preview(&mut engine, store, case, &input).await;
    let action = if weak {
        Action::Copy
    } else {
        Action::Update(local.clone())
    };
    let report = engine
        .apply_import(
            store,
            review.token,
            &selection(case.total, action, true),
            5,
            &mut |_| true,
        )
        .await
        .unwrap();
    assert_eq!(
        (report.added, report.updated, report.skipped),
        (usize::from(weak), usize::from(!weak), case.total - 1)
    );
    let after = heads(store, id).await;
    assert_eq!(after.len(), case.selected + usize::from(weak));
    let chosen = if weak {
        assert_eq!(
            store.head(id, local.record).await.unwrap(),
            Some(local.clone())
        );
        let new: Vec<_> = after
            .iter()
            .filter(|head| !before.heads.iter().any(|old| old.record == head.record))
            .collect();
        assert_eq!(new.len(), 1);
        new[0].clone()
    } else {
        store.head(id, local.record).await.unwrap().unwrap()
    };
    for old in &before.heads {
        if old.record != local.record {
            assert_eq!(
                store.head(id, old.record).await.unwrap().as_ref(),
                Some(old)
            );
        }
    }
    for object in &before.objects {
        assert_eq!(
            store.object(id, object.head.revision).await.unwrap(),
            object.wire
        );
    }
    assert_eq!(
        store.object(id, original.revision).await.unwrap(),
        original_wire
    );
    let wire = store.object(id, chosen.revision).await.unwrap();
    let mut opened = envelope::open(
        &wire,
        vault.keys(),
        vault.anchor(),
        Some(&chosen.revision),
        MAX_OPEN_MEMORY,
    )
    .unwrap();
    assert_eq!(opened.revision.header().metadata.epoch, 5);
    assert_eq!(
        opened.revision.header().parents,
        if weak { vec![] } else { vec![local.revision] }
    );
    let origin = &opened.record.extra[ORIGIN];
    assert!(same_source(
        field(origin, "source"),
        &changed.items[0].source
    ));
    let attributes =
        import::attribute_record(changed.items[0].source_attributes(MAX_OPEN_MEMORY).unwrap());
    same_map(field(origin, "attributes"), &attributes.extra["attributes"]);
    retired
        .extra
        .insert("origin".into(), opened.record.extra.remove(ORIGIN).unwrap());
    assert_eq!(
        opened
            .record
            .encode_content(MAX_OPEN_MEMORY)
            .unwrap()
            .bytes
            .as_slice(),
        changed.items[0].record_bytes()
    );
    assert!(search(&mut engine, store, LOCAL).await.is_empty());
    assert!(search(&mut engine, store, SOURCE).await.is_empty());
    let repeated = preview(&mut engine, store, case, &input).await;
    assert_eq!(repeated.items[0].matching, Match::Duplicate);
    backup_roundtrip(&mut engine, store, created, repeated.token).await;
    assert!(engine.import_plan(repeated.token).is_err());
    let restored = preview(&mut engine, store, case, &input).await;
    assert_eq!(restored.items[0].matching, Match::Duplicate);
    engine.cancel_import(restored.token).unwrap();
    assert!(search(&mut engine, store, LOCAL).await.is_empty());
    assert!(search(&mut engine, store, SOURCE).await.is_empty());
}

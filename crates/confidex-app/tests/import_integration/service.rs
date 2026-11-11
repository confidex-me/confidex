use super::*;
use confidex_app::{Draft, Response, import_flow as flow};
use zeroize::Zeroizing;

pub fn cases() -> Vec<&'static Case> {
    assert!(
        flow::FORMATS.iter().all(|format| crate::cases::CASES
            .iter()
            .chain(crate::cases::KDBX)
            .any(|case| case.format == *format)),
        "each registered format needs a shared fixture"
    );
    crate::cases::CASES
        .iter()
        .chain(crate::cases::KDBX)
        .filter(|case| flow::FORMATS.contains(&case.format))
        .collect()
}

pub(super) async fn exchange<S: Store>(
    engine: &mut Engine,
    store: &mut S,
    command: flow::Command,
) -> Result<flow::Reply, flow::Error> {
    let encoded = Zeroizing::new(
        serde_json::to_vec(&Request {
            generation: 37,
            command: Command::VendorImport(command),
        })
        .unwrap(),
    );
    let mut request: Request = serde_json::from_slice(&encoded).unwrap();
    drop(encoded);
    let response = engine.execute(store, &mut Keys, &mut request).await;
    let encoded = Zeroizing::new(serde_json::to_vec(&response).unwrap());
    let response: Response = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(response.generation, 37);
    let Output::VendorImport(result) = response.result.unwrap() else {
        panic!("import dispatch")
    };
    result
}

pub(super) async fn prepare<S: Store>(
    engine: &mut Engine,
    store: &mut S,
    case: &Case,
    name: &str,
) -> confidex_app::import_apply::Review {
    let mut options = case.options("");
    let mapping = options.csv.take();
    let mut reply = exchange(
        engine,
        store,
        flow::Command::Prepare {
            operation: 11,
            file_name: name.into(),
            format: Some(case.format),
            options,
            bytes: case.input.to_vec(),
        },
    )
    .await
    .unwrap();
    let mut operation = 11;
    if let flow::Reply::CsvRequired {
        operation: returned,
        ref setup,
    } = reply
    {
        assert_eq!(case.format, import::Format::Csv);
        let mapping = mapping.unwrap();
        let token = setup.token;
        assert_eq!(
            (returned, setup.file.name.as_str(), setup.file.bytes),
            (11, name, case.input.len())
        );
        assert!(!setup.mapping.header && setup.profiles.is_empty());
        assert_eq!(setup.mapping.columns.len(), mapping.columns.len());
        assert!(
            setup
                .mapping
                .columns
                .iter()
                .all(|column| column.name.is_empty() && column.target == "secret/v1")
        );
        reply = exchange(
            engine,
            store,
            flow::Command::ConfigureCsv {
                operation: 16,
                token,
                delimiter: mapping.delimiter,
                header: mapping.header,
            },
        )
        .await
        .unwrap();
        let flow::Reply::CsvRequired {
            operation: returned,
            ref setup,
        } = reply
        else {
            panic!("CSV header")
        };
        assert_eq!(
            (
                returned,
                setup.token,
                setup.mapping.delimiter,
                setup.mapping.header
            ),
            (16, token, mapping.delimiter, mapping.header)
        );
        assert!(
            setup
                .mapping
                .columns
                .iter()
                .all(|column| column.target == "secret/v1")
        );
        let reviewed = exchange(
            engine,
            store,
            flow::Command::PreviewCsv {
                operation: 17,
                token,
                mapping: mapping.clone(),
            },
        )
        .await
        .unwrap();
        let flow::Reply::Reviewed {
            operation: returned,
            ref review,
            ..
        } = reviewed
        else {
            panic!("CSV preview")
        };
        assert_eq!(returned, 17);
        assert_ne!(review.token, token);
        let old = review.token;
        exchange(
            engine,
            store,
            flow::Command::ConfigureCsv {
                operation: 18,
                token,
                delimiter: mapping.delimiter,
                header: mapping.header,
            },
        )
        .await
        .unwrap();
        stale_review(engine, store, old).await;
        reply = exchange(
            engine,
            store,
            flow::Command::PreviewCsv {
                operation: 19,
                token,
                mapping,
            },
        )
        .await
        .unwrap();
        let flow::Reply::Reviewed { ref review, .. } = reply else {
            panic!("CSV re-preview")
        };
        assert_ne!(review.token, old);
        assert_ne!(review.token, token);
        operation = 19;
    }
    if let flow::Reply::PasswordRequired {
        token,
        ref file,
        operation: returned,
    } = reply
    {
        assert_eq!(case.format, import::Format::BitwardenEncryptedJson);
        assert_eq!(
            (returned, file.name.as_str(), file.bytes),
            (11, name, case.input.len())
        );
        assert!(matches!(
            exchange(
                engine,
                store,
                flow::Command::Unlock {
                    operation: 12,
                    token,
                    password: "wrong".into(),
                }
            )
            .await,
            Err(flow::Error::Authentication)
        ));
        reply = exchange(
            engine,
            store,
            flow::Command::Unlock {
                operation: 13,
                token,
                password: crate::cases::EXPORT_PASSWORD.into(),
            },
        )
        .await
        .unwrap();
        operation = 13;
        assert!(matches!(
            exchange(
                engine,
                store,
                flow::Command::Unlock {
                    operation: 14,
                    token,
                    password: crate::cases::EXPORT_PASSWORD.into(),
                }
            )
            .await,
            Err(flow::Error::Apply(Error::InvalidSession))
        ));
    }
    if case.format == import::Format::Kdbx {
        let flow::Reply::KdbxRequired {
            token,
            ref file,
            operation: returned,
        } = reply
        else {
            panic!("KDBX credentials")
        };
        assert_eq!(
            (returned, file.name.as_str(), file.bytes),
            (11, name, case.input.len())
        );
        assert!(matches!(
            exchange(
                engine,
                store,
                flow::Command::UnlockKdbx {
                    operation: 21,
                    token,
                    password: Some("PUBLIC-WRONG-DATABASE-PASSWORD".into()),
                    keyfile: case.keyfile.map(<[u8]>::to_vec),
                }
            )
            .await,
            Err(flow::Error::Authentication)
        ));
        reply = exchange(
            engine,
            store,
            flow::Command::UnlockKdbx {
                operation: 22,
                token,
                password: case.password.map(str::to_owned),
                keyfile: case.keyfile.map(<[u8]>::to_vec),
            },
        )
        .await
        .unwrap();
        operation = 22;
        assert!(matches!(
            exchange(
                engine,
                store,
                flow::Command::UnlockKdbx {
                    operation: 23,
                    token,
                    password: case.password.map(str::to_owned),
                    keyfile: case.keyfile.map(<[u8]>::to_vec),
                }
            )
            .await,
            Err(flow::Error::Apply(Error::InvalidSession))
        ));
    }
    let flow::Reply::Reviewed {
        operation: returned,
        file,
        review,
    } = reply
    else {
        panic!("review")
    };
    assert_eq!(
        (returned, file.name.as_str(), file.bytes),
        (operation, name, case.input.len())
    );
    assert_eq!(review.items.len(), case.total);
    let actual = engine.import_plan(review.token).unwrap();
    let expected = case.plan();
    assert_eq!(actual.container_status, expected.container_status);
    assert_eq!(
        actual.container_attributes_bytes(),
        expected.container_attributes_bytes()
    );
    for (actual, expected) in actual.items.iter().zip(&expected.items) {
        assert_eq!(actual.record_bytes(), expected.record_bytes());
        assert_eq!(
            actual.source_attributes_bytes(),
            expected.source_attributes_bytes()
        );
        assert_eq!(actual.status, expected.status);
    }
    review
}

async fn stale<S: Store>(engine: &mut Engine, store: &mut S, token: [u8; 16]) {
    assert!(matches!(
        exchange(engine, store, flow::Command::Rows { token, start: 0 }).await,
        Err(flow::Error::Apply(Error::InvalidSession))
    ));
}

pub(super) async fn stale_review<S: Store>(engine: &mut Engine, store: &mut S, token: [u8; 16]) {
    let expected = crate::cases::CASES[0].plan();
    for command in [
        flow::Command::Rows { token, start: 0 },
        flow::Command::Preview { token, index: 0 },
        flow::Command::Candidates {
            token,
            index: 0,
            after: 0,
        },
        flow::Command::Apply {
            operation: 41,
            token,
            selection: choices(&expected),
            epoch: 42,
        },
    ] {
        assert!(matches!(
            exchange(engine, store, command).await,
            Err(flow::Error::Apply(Error::InvalidSession))
        ));
    }
}

async fn pending_credentials<S: Store>(
    engine: &mut Engine,
    store: &mut S,
    case: &Case,
) -> [u8; 16] {
    let reply = exchange(
        engine,
        store,
        flow::Command::Prepare {
            operation: 40,
            file_name: "public-encrypted-source.bin".into(),
            format: Some(case.format),
            options: case.options(""),
            bytes: case.input.to_vec(),
        },
    )
    .await
    .unwrap();
    match reply {
        flow::Reply::PasswordRequired { token, .. }
            if case.format == import::Format::BitwardenEncryptedJson =>
        {
            token
        }
        flow::Reply::KdbxRequired { token, .. } if case.format == import::Format::Kdbx => token,
        _ => panic!("credentials required"),
    }
}

async fn stale_credentials<S: Store>(
    engine: &mut Engine,
    store: &mut S,
    case: &Case,
    token: [u8; 16],
    expected: flow::Error,
) {
    let command = if case.format == import::Format::Kdbx {
        flow::Command::UnlockKdbx {
            operation: 42,
            token,
            password: case.password.map(str::to_owned),
            keyfile: case.keyfile.map(<[u8]>::to_vec),
        }
    } else {
        flow::Command::Unlock {
            operation: 42,
            token,
            password: case.password.unwrap().into(),
        }
    };
    assert!(matches!(exchange(engine, store, command).await, Err(actual) if actual == expected));
}

async fn unlock<S: Store>(engine: &mut Engine, store: &mut S, created: &Created) {
    assert!(matches!(
        command(
            engine,
            store,
            Command::Unlock {
                vault: created.info.id,
                password: PASSWORD.into(),
                key: created.key.clone(),
                remember: false,
            }
        )
        .await,
        Output::Opened { .. }
    ));
}

pub async fn isolation<S: Store>(store: &mut S) -> [VaultId; 2] {
    let case = &crate::cases::CASES[0];
    let (mut engine, first) = faults::setup(store).await;
    faults::write_concurrent(store, first.info.id, &first.key).await;
    let first_before = store.snapshot(first.info.id).await.unwrap();
    let review = prepare(&mut engine, store, case, "before-lock.json").await;
    assert!(matches!(
        command(&mut engine, store, Command::Lock).await,
        Output::Locked
    ));
    stale_review(&mut engine, store, review.token).await;
    unlock(&mut engine, store, &first).await;
    stale_review(&mut engine, store, review.token).await;
    same_snapshot(&first_before, &store.snapshot(first.info.id).await.unwrap());

    let encrypted = &crate::cases::CASES[6];
    let kdbx = &crate::cases::KDBX[0];
    for credentials in [encrypted, kdbx] {
        let token = pending_credentials(&mut engine, store, credentials).await;
        exchange(
            &mut engine,
            store,
            flow::Command::Cancel { token: Some(token) },
        )
        .await
        .unwrap();
        stale_credentials(
            &mut engine,
            store,
            credentials,
            token,
            flow::Error::Apply(Error::InvalidSession),
        )
        .await;
        let token = pending_credentials(&mut engine, store, credentials).await;
        command(&mut engine, store, Command::Lock).await;
        stale_credentials(
            &mut engine,
            store,
            credentials,
            token,
            flow::Error::App(confidex_app::Error::Locked),
        )
        .await;
        unlock(&mut engine, store, &first).await;
        stale_credentials(
            &mut engine,
            store,
            credentials,
            token,
            flow::Error::Apply(Error::InvalidSession),
        )
        .await;
        same_snapshot(&first_before, &store.snapshot(first.info.id).await.unwrap());
    }

    let token = pending_credentials(&mut engine, store, encrypted).await;
    let Output::Created(second) = command(
        &mut engine,
        store,
        Command::Create {
            name: "Public second import destination".into(),
            password: PASSWORD.into(),
            remember: false,
        },
    )
    .await
    else {
        panic!("second destination")
    };
    assert_ne!(first.info.id, second.info.id);
    faults::write_concurrent(store, second.info.id, &second.key).await;
    let second_before = store.snapshot(second.info.id).await.unwrap();
    stale_credentials(
        &mut engine,
        store,
        encrypted,
        token,
        flow::Error::Apply(Error::InvalidSession),
    )
    .await;

    unlock(&mut engine, store, &first).await;
    let token = pending_credentials(&mut engine, store, kdbx).await;
    unlock(&mut engine, store, &second).await;
    stale_credentials(
        &mut engine,
        store,
        kdbx,
        token,
        flow::Error::Apply(Error::InvalidSession),
    )
    .await;

    let review = prepare(&mut engine, store, case, "second-vault.json").await;
    unlock(&mut engine, store, &first).await;
    stale_review(&mut engine, store, review.token).await;
    same_snapshot(&first_before, &store.snapshot(first.info.id).await.unwrap());
    same_snapshot(
        &second_before,
        &store.snapshot(second.info.id).await.unwrap(),
    );

    let review = prepare(&mut engine, store, case, "fresh-session.json").await;
    exchange(
        &mut engine,
        store,
        flow::Command::Cancel {
            token: Some(review.token),
        },
    )
    .await
    .unwrap();
    for (created, before) in [(&first, &first_before), (&second, &second_before)] {
        let mut reopened = index::open(store, created).await;
        assert_eq!(
            search(&mut reopened, store, faults::CONCURRENT).await,
            [before.heads[0].record]
        );
        same_snapshot(before, &store.snapshot(created.info.id).await.unwrap());
    }
    [first.info.id, second.info.id]
}

pub async fn first<S: Store>(store: &mut S, case: &Case) -> Created {
    let (mut engine, created) = faults::setup(store).await;
    let id = created.info.id;
    let before = store.snapshot(id).await.unwrap();
    let flow::Reply::Begun { vault, formats } = exchange(&mut engine, store, flow::Command::Begin)
        .await
        .unwrap()
    else {
        panic!("begin")
    };
    assert_eq!(vault, id);
    assert_eq!(formats, flow::FORMATS);
    let review = prepare(&mut engine, store, case, "misleading.csv").await;
    let wrong = if case.format == import::Format::BitwardenJson {
        import::Format::KeepassXml
    } else {
        import::Format::BitwardenJson
    };
    assert!(matches!(
        exchange(
            &mut engine,
            store,
            flow::Command::Prepare {
                operation: 15,
                file_name: "different.json".into(),
                format: Some(wrong),
                options: case.options(""),
                bytes: case.input.to_vec(),
            }
        )
        .await,
        Err(flow::Error::InvalidOptions)
    ));
    stale(&mut engine, store, review.token).await;
    same_snapshot(&before, &store.snapshot(id).await.unwrap());
    let review = prepare(&mut engine, store, case, "another-name.bin").await;
    assert!(matches!(
        exchange(
            &mut engine,
            store,
            flow::Command::Cancel {
                token: Some(review.token)
            }
        )
        .await
        .unwrap(),
        flow::Reply::Canceled
    ));
    stale(&mut engine, store, review.token).await;
    same_snapshot(&before, &store.snapshot(id).await.unwrap());
    let review = prepare(&mut engine, store, case, "confirmed.bin").await;
    let expected = case.plan();
    let mut previews: Vec<Option<Draft>> = vec![None; case.total];
    let mut start = 0;
    loop {
        let flow::Reply::Rows {
            token,
            start: returned,
            rows,
            next,
        } = exchange(
            &mut engine,
            store,
            flow::Command::Rows {
                token: review.token,
                start,
            },
        )
        .await
        .unwrap()
        else {
            panic!("rows")
        };
        assert_eq!((token, returned), (review.token, start));
        assert!(!rows.is_empty() && rows.len() <= flow::PAGE_SIZE);
        for (offset, row) in rows.iter().enumerate() {
            assert_eq!(row.index, start + offset);
            let item = &expected.items[row.index];
            let record = item.record(MAX_OPEN_MEMORY).unwrap();
            assert_eq!(row.title, record.extra["confidex.title"].as_str().unwrap());
            assert_eq!(row.fields, record.entries.len());
            assert_eq!(row.source_account, item.source.account);
            assert_eq!(row.source_vault, item.source.vault);
            assert_eq!(row.diagnostics, item.diagnostics);
            let flow::Reply::Preview {
                token,
                index,
                draft,
            } = exchange(
                &mut engine,
                store,
                flow::Command::Preview {
                    token: review.token,
                    index: row.index,
                },
            )
            .await
            .unwrap()
            else {
                panic!("preview")
            };
            assert_eq!((token, index), (review.token, row.index));
            assert_eq!(draft.title, row.title);
            assert_eq!(draft.tags, record.tags);
            previews[index] = Some(draft);
        }
        let end = start + rows.len();
        if let Some(next) = next {
            assert_eq!(next, end);
            start = next;
        } else {
            assert_eq!(end, case.total);
            break;
        }
    }
    same_snapshot(&before, &store.snapshot(id).await.unwrap());
    let flow::Reply::Applied { operation, report } = exchange(
        &mut engine,
        store,
        flow::Command::Apply {
            operation: 19,
            token: review.token,
            selection: choices(&expected),
            epoch: 42,
        },
    )
    .await
    .unwrap() else {
        panic!("apply")
    };
    assert_eq!(
        (operation, report.added, report.updated, report.skipped),
        (19, case.selected, 0, case.total - case.selected)
    );
    stale(&mut engine, store, review.token).await;
    let selected = heads(store, id).await;
    let records = verify(store, &created, case, &expected, &selected).await;
    for (index, head) in &records {
        let Output::Draft(draft) = command(
            &mut engine,
            store,
            Command::Open {
                record: head.record,
            },
        )
        .await
        else {
            panic!("stored draft")
        };
        let preview = previews[*index].as_ref().unwrap();
        assert_eq!(draft.title, preview.title);
        assert_eq!(draft.tags, preview.tags);
        let preview = Zeroizing::new(serde_json::to_vec(&preview.fields).unwrap());
        let actual = Zeroizing::new(serde_json::to_vec(&draft.fields).unwrap());
        assert_eq!(
            *actual, *preview,
            "{} preview changed stored fields",
            case.name
        );
    }
    search_checks(&mut engine, store, case, &expected, &records).await;
    created
}

pub async fn reopened<S: Store>(store: &mut S, case: &Case, created: &Created) {
    let mut engine = index::open(store, created).await;
    let before = store.snapshot(created.info.id).await.unwrap();
    let review = prepare(&mut engine, store, case, "renamed-export.bin").await;
    let expected = case.plan();
    for (item, state) in expected.items.iter().zip(&review.items) {
        if accepted(item.status) {
            assert_eq!(state.matching, Match::Duplicate);
        }
    }
    let mut selection = choices(&expected);
    for choice in &mut selection.choices {
        choice.action = Action::Skip;
    }
    let flow::Reply::Applied { operation, report } = exchange(
        &mut engine,
        store,
        flow::Command::Apply {
            operation: 20,
            token: review.token,
            selection,
            epoch: 43,
        },
    )
    .await
    .unwrap() else {
        panic!("skip")
    };
    assert_eq!(
        (operation, report.added, report.updated, report.skipped),
        (20, 0, 0, case.total)
    );
    same_snapshot(&before, &store.snapshot(created.info.id).await.unwrap());
    let records = verify(store, created, case, &expected, &before.heads).await;
    search_checks(&mut engine, store, case, &expected, &records).await;
}

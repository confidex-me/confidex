#![cfg(not(target_arch = "wasm32"))]
use confidex_app::{
    Command, DeviceKeys, Engine, Output, Request, import, import_apply as apply,
    import_flow as flow,
};
use confidex_storage::{SqliteStore, Store};
struct Keys;
impl DeviceKeys for Keys {
    async fn remove(&mut self, _: [u8; 16]) -> bool {
        true
    }
    async fn load(&mut self, _: [u8; 16]) -> Option<String> {
        None
    }
    async fn save(&mut self, _: [u8; 16], _: &str) -> bool {
        false
    }
}
const FILE: &[u8] = br#"{"encrypted":false,"folders":[],"items":[{"id":"public-id","type":1,"name":"Public account","login":{"username":"public-user","password":"hidden-password","uris":[{"uri":"https://public.example.invalid"}]}}]}"#;
#[test]
fn resource_limits_are_not_displayed_as_workload_totals() {
    let progress = flow::Progress::from(import::Progress {
        phase: import::Phase::Map,
        current: 1,
        total: 10000,
    });
    assert_eq!(progress.total, 0);
    let progress = flow::Progress::from(apply::Progress {
        phase: apply::Phase::Catalog,
        current: 1,
        total: 100000,
    });
    assert_eq!(progress.total, 0);
    let progress = flow::Progress::from(apply::Progress {
        phase: apply::Phase::Seal,
        current: 1,
        total: 8,
    });
    assert_eq!(progress.total, 8);
}
fn prepare(bytes: &[u8]) -> flow::Command {
    let mut options = import::Options::default();
    options.source_instance = Some("public-source-account".into());
    flow::Command::Prepare {
        operation: 1,
        file_name: "public-export.json".into(),
        format: None,
        options,
        bytes: bytes.to_vec(),
    }
}
#[test]
fn csv_headers_are_explicit_and_remapping_invalidates_the_old_preview() {
    tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
        const CSV:&[u8]=b"name,url,username,password,note\nPublic CSV,https://csv.example.invalid,public-user,csv-private-password,csv-private-note\n";
        let mut engine=Engine::default();
        let mut store=SqliteStore::open(std::path::Path::new(":memory:")).unwrap();
        let created=engine.execute(&mut store,&mut Keys,&mut Request {generation:1,command:Command::Create {name:"Public CSV destination".into(),password:"public-test-password".into(),remember:false}}).await;
        let Ok(Output::Created(created))=created.result else {panic!("create")};
        let mut command=prepare(CSV);
        if let flow::Command::Prepare {format,file_name,..}=&mut command { *format=Some(import::Format::Csv); *file_name="public.csv".into(); }
        let flow::Reply::CsvRequired {setup,..}=engine.execute_import(&mut store,&mut command,&mut flow::Quiet).await.unwrap() else {panic!("columns")};
        assert_eq!(setup.mapping.columns.len(),5);
        assert!(setup.mapping.columns.iter().all(|column|column.name.is_empty()&&column.target=="secret/v1"));
        assert!(setup.profiles.is_empty());
        assert!(!serde_json::to_string(&setup).unwrap().contains("csv-private"));
        let flow::Reply::CsvRequired {setup,..}=engine.execute_import(&mut store,&mut flow::Command::ConfigureCsv {operation:2,token:setup.token,delimiter:b',',header:true},&mut flow::Quiet).await.unwrap() else {panic!("headers")};
        assert_eq!(setup.profiles.len(),1);
        assert_eq!(setup.profiles[0].id,"chromium");
        assert_eq!(setup.mapping.columns[3].name,"password");
        assert!(!serde_json::to_string(&setup).unwrap().contains("csv-private"));
        let mapping=setup.profiles[0].mapping.clone();
        let flow::Reply::Reviewed {review,..}=engine.execute_import(&mut store,&mut flow::Command::PreviewCsv {operation:3,token:setup.token,mapping:mapping.clone()},&mut flow::Quiet).await.unwrap() else {panic!("preview")};
        assert_eq!(review.items.len(),1);
        let flow::Reply::Preview {draft,..}=engine.execute_import(&mut store,&mut flow::Command::Preview {token:review.token,index:0},&mut flow::Quiet).await.unwrap() else {panic!("fields")};
        assert!(draft.fields.iter().any(|field|field.type_name=="password/v1"&&field.values.values().any(|value|value=="csv-private-password")));
        assert!(draft.fields.iter().any(|field|field.type_name=="secure-note/v1"));
        assert!(store.heads(created.info.id,None).await.unwrap().is_empty());
        let flow::Reply::CsvRequired {setup:reset,..}=engine.execute_import(&mut store,&mut flow::Command::ConfigureCsv {operation:4,token:setup.token,delimiter:b',',header:false},&mut flow::Quiet).await.unwrap() else {panic!("reset")};
        assert!(reset.mapping.columns.iter().all(|column|column.name.is_empty()&&column.target=="secret/v1"));
        assert!(engine.import_plan(review.token).is_err());
        assert!(engine.execute_import(&mut store,&mut flow::Command::Apply {operation:5,token:review.token,selection:apply::Selection {container_reviewed:true,choices:vec![apply::Choice {action:apply::Action::Create,reviewed:true}]},epoch:1},&mut flow::Quiet).await.is_err());
        let mut invalid=mapping.clone();invalid.columns[0].target="discard".into();
        assert!(engine.execute_import(&mut store,&mut flow::Command::PreviewCsv {operation:6,token:setup.token,mapping:invalid},&mut flow::Quiet).await.is_err());
        let flow::Reply::Reviewed {review,..}=engine.execute_import(&mut store,&mut flow::Command::PreviewCsv {operation:7,token:setup.token,mapping},&mut flow::Quiet).await.unwrap() else {panic!("re-preview")};
        assert!(store.heads(created.info.id,None).await.unwrap().is_empty());
        engine.execute_import(&mut store,&mut flow::Command::Apply {operation:8,token:review.token,selection:apply::Selection {container_reviewed:true,choices:vec![apply::Choice {action:apply::Action::Create,reviewed:true}]},epoch:1},&mut flow::Quiet).await.unwrap();
        assert_eq!(store.heads(created.info.id,None).await.unwrap().len(),1);
        assert!(engine.execute_import(&mut store,&mut flow::Command::ConfigureCsv {operation:9,token:setup.token,delimiter:b',',header:true},&mut flow::Quiet).await.is_err());
        for name in ["{label}","<label>"] {
            let data=format!("{name},password\nPublic,csv-private-password\n");
            let mut command=prepare(data.as_bytes());
            if let flow::Command::Prepare {format,..}=&mut command {*format=Some(import::Format::Csv);}
            assert!(matches!(engine.execute_import(&mut store,&mut command,&mut flow::Quiet).await,Ok(flow::Reply::CsvRequired {..})),"CSV headers can contain braces and angle brackets");
        }
    });
}
#[test]
fn encrypted_exports_retry_in_memory_and_clear_on_cancel_or_lock() {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            const ENCRYPTED: &[u8] =
                include_bytes!("import_fixtures/bitwarden_encrypted_json/pbkdf2-legacy.json");
            const PASSWORD: &str = " Public test-only 密码 é e\u{301} ";
            let mut engine = Engine::default();
            let mut store = SqliteStore::open(std::path::Path::new(":memory:")).unwrap();
            let created = engine
                .execute(
                    &mut store,
                    &mut Keys,
                    &mut Request {
                        generation: 1,
                        command: Command::Create {
                            name: "Public encrypted destination".into(),
                            password: "public-test-password".into(),
                            remember: false,
                        },
                    },
                )
                .await;
            let Ok(Output::Created(created)) = created.result else {
                panic!("create")
            };
            let flow::Reply::PasswordRequired { token, .. } = engine
                .execute_import(&mut store, &mut prepare(ENCRYPTED), &mut flow::Quiet)
                .await
                .unwrap()
            else {
                panic!("password step")
            };
            assert!(store.heads(created.info.id, None).await.unwrap().is_empty());
            assert!(matches!(
                engine
                    .execute_import(
                        &mut store,
                        &mut flow::Command::Unlock {
                            operation: 2,
                            token: [0; 16],
                            password: PASSWORD.into()
                        },
                        &mut flow::Quiet
                    )
                    .await,
                Err(flow::Error::Apply(apply::Error::InvalidSession))
            ));
            for password in ["wrong", PASSWORD.trim()] {
                let mut command = flow::Command::Unlock {
                    operation: 2,
                    token,
                    password: password.into(),
                };
                assert!(matches!(
                    engine
                        .execute_import(&mut store, &mut command, &mut flow::Quiet)
                        .await,
                    Err(flow::Error::Authentication)
                ));
                assert!(
                    matches!(&command,flow::Command::Unlock {password,..} if password.is_empty())
                );
                assert!(store.heads(created.info.id, None).await.unwrap().is_empty());
            }
            let flow::Reply::Reviewed { review, .. } = engine
                .execute_import(
                    &mut store,
                    &mut flow::Command::Unlock {
                        operation: 3,
                        token,
                        password: PASSWORD.into(),
                    },
                    &mut flow::Quiet,
                )
                .await
                .unwrap()
            else {
                panic!("preview")
            };
            assert_eq!(review.items.len(), 3);
            engine
                .execute_import(
                    &mut store,
                    &mut flow::Command::Cancel {
                        token: Some(review.token),
                    },
                    &mut flow::Quiet,
                )
                .await
                .unwrap();
            assert!(matches!(
                engine
                    .execute_import(
                        &mut store,
                        &mut flow::Command::Unlock {
                            operation: 4,
                            token,
                            password: PASSWORD.into()
                        },
                        &mut flow::Quiet
                    )
                    .await,
                Err(flow::Error::Apply(apply::Error::InvalidSession))
            ));
            let flow::Reply::PasswordRequired { token, .. } = engine
                .execute_import(&mut store, &mut prepare(ENCRYPTED), &mut flow::Quiet)
                .await
                .unwrap()
            else {
                panic!("retry source")
            };
            assert!(
                engine
                    .execute_import(
                        &mut store,
                        &mut flow::Command::Cancel {
                            token: Some([0; 16])
                        },
                        &mut flow::Quiet
                    )
                    .await
                    .is_err()
            );
            engine
                .execute_import(
                    &mut store,
                    &mut flow::Command::Cancel { token: Some(token) },
                    &mut flow::Quiet,
                )
                .await
                .unwrap();
            assert!(
                engine
                    .execute_import(
                        &mut store,
                        &mut flow::Command::Unlock {
                            operation: 5,
                            token,
                            password: PASSWORD.into()
                        },
                        &mut flow::Quiet
                    )
                    .await
                    .is_err()
            );
            let mut restricted: serde_json::Value = serde_json::from_slice(ENCRYPTED).unwrap();
            restricted["passwordProtected"] = false.into();
            assert!(matches!(
                engine
                    .execute_import(
                        &mut store,
                        &mut prepare(&serde_json::to_vec(&restricted).unwrap()),
                        &mut flow::Quiet
                    )
                    .await,
                Err(flow::Error::AccountRestricted)
            ));
            let flow::Reply::PasswordRequired { token, .. } = engine
                .execute_import(&mut store, &mut prepare(ENCRYPTED), &mut flow::Quiet)
                .await
                .unwrap()
            else {
                panic!("lock source")
            };
            engine
                .execute(
                    &mut store,
                    &mut Keys,
                    &mut Request {
                        generation: 1,
                        command: Command::Lock,
                    },
                )
                .await
                .result
                .unwrap();
            assert!(matches!(
                engine
                    .execute_import(
                        &mut store,
                        &mut flow::Command::Unlock {
                            operation: 6,
                            token,
                            password: PASSWORD.into()
                        },
                        &mut flow::Quiet
                    )
                    .await,
                Err(flow::Error::App(confidex_app::Error::Locked))
            ));
            engine
                .execute(
                    &mut store,
                    &mut Keys,
                    &mut Request {
                        generation: 1,
                        command: Command::Unlock {
                            vault: created.info.id,
                            password: "public-test-password".into(),
                            key: created.key.clone(),
                            remember: false,
                        },
                    },
                )
                .await
                .result
                .unwrap();
            assert!(matches!(
                engine
                    .execute_import(
                        &mut store,
                        &mut flow::Command::Unlock {
                            operation: 7,
                            token,
                            password: PASSWORD.into()
                        },
                        &mut flow::Quiet
                    )
                    .await,
                Err(flow::Error::Apply(apply::Error::InvalidSession))
            ));
            assert!(store.heads(created.info.id, None).await.unwrap().is_empty());
        });
}
#[test]
fn archive_sources_use_the_shared_preview_and_require_a_matching_format() {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let mut engine = Engine::default();
            let mut store = SqliteStore::open(std::path::Path::new(":memory:")).unwrap();
            let created = engine
                .execute(
                    &mut store,
                    &mut Keys,
                    &mut Request {
                        generation: 1,
                        command: Command::Create {
                            name: "Public archive destination".into(),
                            password: "public-test-password".into(),
                            remember: false,
                        },
                    },
                )
                .await;
            let Ok(Output::Created(created)) = created.result else {
                panic!("create")
            };
            for (format, bytes, count) in [
                (
                    import::Format::Onepassword1pux,
                    include_bytes!("import_fixtures/onepassword_1pux/account.1pux").as_slice(),
                    4,
                ),
                (
                    import::Format::BitwardenZip,
                    include_bytes!("import_fixtures/bitwarden_zip/personal.zip").as_slice(),
                    3,
                ),
            ] {
                let mut command = prepare(bytes);
                let flow::Command::Prepare { format: choice, .. } = &mut command else {
                    unreachable!()
                };
                *choice = Some(format);
                let flow::Reply::Reviewed { review, .. } = engine
                    .execute_import(&mut store, &mut command, &mut flow::Quiet)
                    .await
                    .unwrap()
                else {
                    panic!("review")
                };
                assert_eq!(review.items.len(), count);
                let flow::Reply::Preview { draft, .. } = engine
                    .execute_import(
                        &mut store,
                        &mut flow::Command::Preview {
                            token: review.token,
                            index: 1,
                        },
                        &mut flow::Quiet,
                    )
                    .await
                    .unwrap()
                else {
                    panic!("preview")
                };
                assert!(
                    draft
                        .fields
                        .iter()
                        .any(|field| field.type_name == "file/v1")
                );
                assert!(store.heads(created.info.id, None).await.unwrap().is_empty());
                // File suffixes only suggest a choice; the contents must match it.
                let mut wrong = prepare(bytes);
                if let flow::Command::Prepare { format, .. } = &mut wrong {
                    *format = Some(import::Format::KeepassXml);
                }
                assert!(matches!(
                    engine
                        .execute_import(&mut store, &mut wrong, &mut flow::Quiet)
                        .await,
                    Err(flow::Error::InvalidOptions)
                ));
                assert!(engine.import_plan(review.token).is_err());
            }
            let mut automatic =
                prepare(include_bytes!("import_fixtures/bitwarden_zip/personal.zip"));
            assert!(matches!(
                engine
                    .execute_import(&mut store, &mut automatic, &mut flow::Quiet)
                    .await,
                Err(flow::Error::InvalidOptions)
            ));
            assert!(store.heads(created.info.id, None).await.unwrap().is_empty());
        });
}
#[test]
fn preview_is_private_until_apply_and_repeated_import_is_a_duplicate() {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let mut engine = Engine::default();
            let mut store = SqliteStore::open(std::path::Path::new(":memory:")).unwrap();
            assert!(
                engine
                    .execute_import(&mut store, &mut flow::Command::Begin, &mut flow::Quiet)
                    .await
                    .is_err()
            );
            let response = engine
                .execute(
                    &mut store,
                    &mut Keys,
                    &mut Request {
                        generation: 1,
                        command: Command::Create {
                            name: "Public destination".into(),
                            password: "public-test-password".into(),
                            remember: false,
                        },
                    },
                )
                .await;
            let Ok(Output::Created(created)) = response.result else {
                panic!("create")
            };
            let flow::Reply::Reviewed { review, .. } = engine
                .execute_import(&mut store, &mut prepare(FILE), &mut flow::Quiet)
                .await
                .unwrap()
            else {
                panic!("review")
            };
            assert_eq!(review.items[0].matching, apply::Match::New);
            assert!(store.heads(created.info.id, None).await.unwrap().is_empty());
            let flow::Reply::Rows { rows, next, .. } = engine
                .execute_import(
                    &mut store,
                    &mut flow::Command::Rows {
                        token: review.token,
                        start: 0,
                    },
                    &mut flow::Quiet,
                )
                .await
                .unwrap()
            else {
                panic!("rows")
            };
            assert_eq!(rows.len(), 1);
            assert!(next.is_none());
            assert_eq!(rows[0].title, "Public account");
            let json = serde_json::to_string(&rows).unwrap();
            assert!(!json.contains("hidden-password"));
            assert!(!json.contains("public-user"));
            let flow::Reply::Preview { draft, .. } = engine
                .execute_import(
                    &mut store,
                    &mut flow::Command::Preview {
                        token: review.token,
                        index: 0,
                    },
                    &mut flow::Quiet,
                )
                .await
                .unwrap()
            else {
                panic!("preview")
            };
            assert!(
                draft
                    .fields
                    .iter()
                    .any(|field| field.type_name == "password/v1"
                        && field.values.values().any(|text| text == "hidden-password"))
            );
            assert!(
                engine
                    .execute_import(
                        &mut store,
                        &mut flow::Command::Rows {
                            token: [9; 16],
                            start: 0
                        },
                        &mut flow::Quiet
                    )
                    .await
                    .is_err()
            );
            let selection = apply::Selection {
                container_reviewed: true,
                choices: vec![apply::Choice {
                    action: apply::Action::Create,
                    reviewed: true,
                }],
            };
            assert!(matches!(
                engine
                    .execute_import(
                        &mut store,
                        &mut flow::Command::Apply {
                            operation: 2,
                            token: review.token,
                            selection,
                            epoch: 1
                        },
                        &mut flow::Quiet
                    )
                    .await
                    .unwrap(),
                flow::Reply::Applied {
                    report: apply::Report { added: 1, .. },
                    ..
                }
            ));
            let flow::Reply::Reviewed { review, .. } = engine
                .execute_import(&mut store, &mut prepare(FILE), &mut flow::Quiet)
                .await
                .unwrap()
            else {
                panic!("repeat")
            };
            assert_eq!(review.items[0].matching, apply::Match::Duplicate);
            let flow::Reply::Candidates { candidates, .. } = engine
                .execute_import(
                    &mut store,
                    &mut flow::Command::Candidates {
                        token: review.token,
                        index: 0,
                        after: 0,
                    },
                    &mut flow::Quiet,
                )
                .await
                .unwrap()
            else {
                panic!("candidates")
            };
            assert_eq!(candidates.items[0].title, "Public account");
            assert_eq!(store.heads(created.info.id, None).await.unwrap().len(), 1);
            engine
                .execute_import(
                    &mut store,
                    &mut flow::Command::Cancel {
                        token: Some(review.token),
                    },
                    &mut flow::Quiet,
                )
                .await
                .unwrap();
            assert!(engine.import_plan(review.token).is_err());
            assert!(
                engine
                    .execute_import(&mut store, &mut prepare(b"not an export"), &mut flow::Quiet)
                    .await
                    .is_err()
            );
            assert_eq!(store.heads(created.info.id, None).await.unwrap().len(), 1);
            let oversized = serde_json::json!({"encrypted":false,"folders":[],"items":[{"type":1,"name":"Public large fields","fields":(0..40).map(|i|serde_json::json!({"type":0,"name":format!("Field {i}"),"value":"a".repeat(65536)})).collect::<Vec<_>>(),"login":{"username":"public","password":"public-test-password"}}]});
            let result=engine.execute_import(&mut store,&mut prepare(&serde_json::to_vec(&oversized).unwrap()),&mut flow::Quiet).await;
            assert!(matches!(result,Err(flow::Error::Parse(import::Error {kind:import::ErrorKind::Limit,..}))));
            assert_eq!(store.heads(created.info.id, None).await.unwrap().len(), 1);
        });
}

#[path = "import_flow/kdbx.rs"]
mod kdbx;

use super::*;

const PASSWORD: &str = "PUBLIC-FIXTURE-DATABASE";
const KEY: &[u8] = include_bytes!("../import_fixtures/kdbx/public.key");

#[test]
fn kdbx_credentials_are_explicit_retryable_and_never_write_before_apply() {
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
                            name: "Public KDBX destination".into(),
                            password: "public-test-password".into(),
                            remember: false,
                        },
                    },
                )
                .await;
            let Ok(Output::Created(created)) = created.result else {
                panic!("create")
            };
            for (input, password, keyfile) in [
                (
                    include_bytes!("../import_fixtures/kdbx/password.kdbx").as_slice(),
                    Some(PASSWORD),
                    None,
                ),
                (
                    include_bytes!("../import_fixtures/kdbx/keyfile.kdbx").as_slice(),
                    None,
                    Some(KEY),
                ),
                (
                    include_bytes!("../import_fixtures/kdbx/both.kdbx").as_slice(),
                    Some(PASSWORD),
                    Some(KEY),
                ),
                (
                    include_bytes!("../import_fixtures/kdbx/empty-password.kdbx").as_slice(),
                    Some(""),
                    None,
                ),
                (
                    include_bytes!("../import_fixtures/kdbx/empty-password-keyfile.kdbx")
                        .as_slice(),
                    Some(""),
                    Some(KEY),
                ),
            ] {
                let flow::Reply::KdbxRequired { token, .. } = engine
                    .execute_import(&mut store, &mut prepare(input), &mut flow::Quiet)
                    .await
                    .unwrap()
                else {
                    panic!("credentials")
                };
                let mut absent = flow::Command::UnlockKdbx {
                    operation: 2,
                    token,
                    password: None,
                    keyfile: None,
                };
                assert_eq!(
                    engine
                        .execute_import(&mut store, &mut absent, &mut flow::Quiet)
                        .await
                        .err(),
                    Some(flow::Error::InvalidOptions)
                );
                let mut oversized = flow::Command::UnlockKdbx {
                    operation: 3,
                    token,
                    password: None,
                    keyfile: Some(vec![0; flow::MAX_KEYFILE_BYTES + 1]),
                };
                assert_eq!(
                    engine
                        .execute_import(&mut store, &mut oversized, &mut flow::Quiet)
                        .await
                        .err(),
                    Some(flow::Error::InvalidOptions)
                );
                let mut wrong = flow::Command::UnlockKdbx {
                    operation: 4,
                    token,
                    password: Some(
                        if password.is_none() {
                            ""
                        } else {
                            "PUBLIC-WRONG-PASSWORD"
                        }
                        .into(),
                    ),
                    keyfile: keyfile.map(<[u8]>::to_vec),
                };
                assert_eq!(
                    engine
                        .execute_import(&mut store, &mut wrong, &mut flow::Quiet)
                        .await
                        .err(),
                    Some(flow::Error::Authentication)
                );
                assert!(matches!(
                    &wrong,
                    flow::Command::UnlockKdbx {
                        password: None,
                        keyfile: None,
                        ..
                    }
                ));
                assert!(store.heads(created.info.id, None).await.unwrap().is_empty());
                let mut correct = flow::Command::UnlockKdbx {
                    operation: 5,
                    token,
                    password: password.map(str::to_owned),
                    keyfile: keyfile.map(<[u8]>::to_vec),
                };
                let flow::Reply::Reviewed { review, .. } = engine
                    .execute_import(&mut store, &mut correct, &mut flow::Quiet)
                    .await
                    .unwrap()
                else {
                    panic!("preview")
                };
                assert_eq!(review.items.len(), 3);
                assert!(store.heads(created.info.id, None).await.unwrap().is_empty());
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
                assert!(
                    engine
                        .execute_import(
                            &mut store,
                            &mut flow::Command::UnlockKdbx {
                                operation: 6,
                                token,
                                password: password.map(str::to_owned),
                                keyfile: keyfile.map(<[u8]>::to_vec)
                            },
                            &mut flow::Quiet
                        )
                        .await
                        .is_err()
                );
            }
            let input = include_bytes!("../import_fixtures/kdbx/password.kdbx");
            let flow::Reply::KdbxRequired { token, .. } = engine
                .execute_import(&mut store, &mut prepare(input), &mut flow::Quiet)
                .await
                .unwrap()
            else {
                panic!("credentials")
            };
            let flow::Reply::Reviewed { review, .. } = engine
                .execute_import(
                    &mut store,
                    &mut flow::Command::UnlockKdbx {
                        operation: 7,
                        token,
                        password: Some(PASSWORD.into()),
                        keyfile: None,
                    },
                    &mut flow::Quiet,
                )
                .await
                .unwrap()
            else {
                panic!("preview")
            };
            let choices: Vec<_> = review
                .items
                .iter()
                .map(|item| apply::Choice {
                    reviewed: true,
                    action: if matches!(
                        item.status,
                        import::Status::Blocked | import::Status::Excluded
                    ) {
                        apply::Action::Skip
                    } else {
                        apply::Action::Create
                    },
                })
                .collect();
            let expected = choices
                .iter()
                .filter(|choice| choice.action == apply::Action::Create)
                .count();
            assert_eq!(expected, 1);
            let selection = apply::Selection {
                container_reviewed: true,
                choices,
            };
            engine
                .execute_import(
                    &mut store,
                    &mut flow::Command::Apply {
                        operation: 8,
                        token: review.token,
                        selection,
                        epoch: 42,
                    },
                    &mut flow::Quiet,
                )
                .await
                .unwrap();
            assert_eq!(
                store.heads(created.info.id, None).await.unwrap().len(),
                expected
            );
            assert!(
                engine
                    .execute_import(
                        &mut store,
                        &mut flow::Command::UnlockKdbx {
                            operation: 9,
                            token,
                            password: Some(PASSWORD.into()),
                            keyfile: None
                        },
                        &mut flow::Quiet
                    )
                    .await
                    .is_err()
            );
        });
}

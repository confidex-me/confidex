#![cfg(not(target_arch = "wasm32"))]
#[path = "export_flow/proof.rs"]
mod proof;

#[cfg(not(feature = "export-check"))]
#[test]
#[ignore = "Run explicitly in release mode for the seven-format 10000-record failure matrix"]
fn ten_thousand_records_reject_cancellation_storage_failures_and_locked_artifacts() {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("public-load-faults.sqlite");
            let mut store = confidex_storage::SqliteStore::open(&path).unwrap();
            let connection = rusqlite::Connection::open(&path).unwrap();
            let report = proof::load_faults(
                &mut store,
                |stage, enabled| {
                    use proof::StorageFailureStage::Prepare;
                    connection
                        .execute_batch(match (stage, enabled) {
                            (Prepare, true) => "ALTER TABLE objects RENAME TO unavailable_objects",
                            (Prepare, false) => "ALTER TABLE unavailable_objects RENAME TO objects",
                            (_, true) => "ALTER TABLE heads RENAME TO unavailable_heads",
                            (_, false) => "ALTER TABLE unavailable_heads RENAME TO heads",
                        })
                        .unwrap();
                },
                None,
            )
            .await;
            let report = serde_json::to_value(report).unwrap();
            assert_eq!(report["records"], 10_000);
            assert_eq!(report["objects_checked"], 10_002);
            assert_eq!(report["entropy_injected"], false);
            assert_eq!(report["runs"].as_array().unwrap().len(), 7);
            assert!(
                report["runs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|run| run["cases"].as_array().unwrap().len() == 8)
            );
            println!("export-load-faults {report}");
        });
}

#[cfg(not(feature = "export-check"))]
#[test]
#[ignore = "Requires pinned independent readers and KeePassXC CLI"]
fn captured_source_edits_reach_all_writers_and_independent_readers() {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let directory = tempfile::tempdir().unwrap();
            let mut store = confidex_storage::SqliteStore::open(
                &directory.path().join("public-reverse.sqlite"),
            )
            .unwrap();
            for output in proof::reverse_exports(&mut store).await {
                let path = directory.path().join(output.name);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, output.bytes).unwrap();
            }
            let output = std::process::Command::new("node")
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../apps/confidex/web/export-reverse-check.mjs"
                ))
                .arg(directory.path())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            print!("{}", String::from_utf8_lossy(&output.stdout));
        });
}

#[cfg(not(feature = "export-check"))]
#[test]
#[ignore = "Run explicitly in release mode for the complete seven-format 10000-record workload"]
fn ten_thousand_current_records_use_real_storage_and_all_writer_factories() {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let directory = tempfile::tempdir().unwrap();
            let mut store = confidex_storage::SqliteStore::open(
                &directory.path().join("public-export-load.sqlite"),
            )
            .unwrap();
            let started = std::time::Instant::now();
            let report = proof::load(&mut store, || started.elapsed().as_secs_f64() * 1000.0).await;
            println!("export-load {}", serde_json::to_string(&report).unwrap());
        });
}

macro_rules! case {
    ($test:ident, $proof:ident) => {
        #[test]
        fn $test() {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(async {
                    let directory = tempfile::tempdir().unwrap();
                    let mut store = confidex_storage::SqliteStore::open(
                        &directory.path().join("public-export.sqlite"),
                    )
                    .unwrap();
                    proof::$proof(&mut store).await;
                });
        }
    };
}
case!(
    full_current_records_and_chunks_match_the_authenticated_payload,
    current_records
);

#[test]
fn sqlite_read_failures_discard_review_and_artifact_without_changing_the_vault() {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("public-storage-failure.sqlite");
            let mut store = confidex_storage::SqliteStore::open(&path).unwrap();
            let connection = rusqlite::Connection::open(&path).unwrap();
            proof::storage_failure(&mut store, |stage, enabled| {
                use proof::StorageFailureStage::Prepare;
                connection
                    .execute_batch(match (stage, enabled) {
                        (Prepare, true) => "ALTER TABLE objects RENAME TO unavailable_objects",
                        (Prepare, false) => "ALTER TABLE unavailable_objects RENAME TO objects",
                        (_, true) => "ALTER TABLE heads RENAME TO unavailable_heads",
                        (_, false) => "ALTER TABLE unavailable_heads RENAME TO heads",
                    })
                    .unwrap();
            })
            .await;
        });
}
case!(
    loss_consent_and_writer_failures_leave_the_vault_unchanged,
    consent_and_failures
);
case!(
    lock_destination_switch_and_import_drop_old_export_tokens,
    invalidation
);
case!(
    external_head_changes_reject_old_confirmation_and_allow_fresh_selection,
    changed_heads
);
case!(
    cancel_before_during_and_after_writing_publishes_nothing,
    cancellation
);
case!(only_current_non_deleted_records_can_be_selected, tombstones);
case!(
    field_sources_are_bounded_current_and_contain_no_values,
    field_sources
);
case!(
    encrypted_json_writer_uses_current_records_and_clears_failed_sessions,
    encrypted_records
);
#[cfg(not(feature = "export-check"))]
case!(
    registered_kdbx_exports_current_records_and_preserves_the_vault,
    kdbx_registry
);
#[cfg(not(feature = "export-check"))]
case!(
    registered_plain_formats_keep_current_credentials_and_attachment_bytes,
    plain_formats
);
#[cfg(not(feature = "export-check"))]
case!(
    csv_factory_exports_exact_current_columns_with_shared_review_and_chunks,
    csv_factory
);
#[cfg(not(feature = "export-check"))]
case!(
    registered_bitwarden_profiles_export_current_values_without_changing_the_vault,
    bitwarden_profiles
);
#[cfg(feature = "export-check")]
case!(
    registered_diagnostic_formats_use_the_complete_serialized_protocol,
    protocol
);

#[test]
fn corrupted_signature_and_wrong_record_header_reject_the_whole_preview() {
    use confidex_app::{Error, export, export_flow as flow};
    use confidex_storage::Store;
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("public-auth-export.sqlite");
            let mut store = confidex_storage::SqliteStore::open(&path).unwrap();
            let mut fixture = proof::fixture(&mut store).await;
            let id = fixture.created.info.id;
            let review = proof::prepare(&mut store, &mut fixture, proof::Mode::Full).await;
            let original = store.object(id, fixture.head.revision).await.unwrap();
            let mut corrupt = original.clone();
            *corrupt.last_mut().unwrap() ^= 1;
            let connection = rusqlite::Connection::open(&path).unwrap();
            connection
                .execute(
                    "UPDATE objects SET wire=?1 WHERE vault=?2 AND revision=?3",
                    rusqlite::params![&corrupt, &id, &fixture.head.revision],
                )
                .unwrap();
            let before = proof::snapshot(&mut store, id).await;
            assert_eq!(
                fixture
                    .engine
                    .export_fields(&mut store, &fixture.head, 0, &mut |_| true)
                    .await
                    .err(),
                Some(flow::Error::App(Error::Integrity))
            );
            assert_eq!(
                fixture
                    .engine
                    .prepare_export(
                        &mut store,
                        &flow::Selection::All,
                        proof::writer(proof::Mode::Full).0,
                        export::Limits::default(),
                        &mut |_| true
                    )
                    .await
                    .err(),
                Some(flow::Error::App(Error::Integrity))
            );
            assert_eq!(
                fixture.engine.export_rows(review.token, 0).err(),
                Some(flow::Error::InvalidSession)
            );
            assert_eq!(*proof::snapshot(&mut store, id).await, *before);
            connection
                .execute(
                    "UPDATE objects SET wire=?1 WHERE vault=?2 AND revision=?3",
                    rusqlite::params![&original, &id, &fixture.head.revision],
                )
                .unwrap();
            let other = proof::append(
                &mut store,
                &fixture.vault,
                [2; 16],
                None,
                &proof::content(),
                3,
            )
            .await;
            let before = proof::snapshot(&mut store, id).await;
            connection
                .execute(
                    "UPDATE heads SET revision=?1 WHERE vault=?2 AND record=?3",
                    rusqlite::params![&other.revision, &id, &fixture.head.record],
                )
                .unwrap();
            assert_eq!(
                fixture
                    .engine
                    .export_fields(
                        &mut store,
                        &confidex_storage::Head {
                            record: fixture.head.record,
                            revision: other.revision
                        },
                        0,
                        &mut |_| true
                    )
                    .await
                    .err(),
                Some(flow::Error::App(Error::Integrity))
            );
            assert_eq!(
                fixture
                    .engine
                    .prepare_export(
                        &mut store,
                        &flow::Selection::All,
                        proof::writer(proof::Mode::Full).0,
                        export::Limits::default(),
                        &mut |_| true
                    )
                    .await
                    .err(),
                Some(flow::Error::App(Error::Integrity))
            );
            assert_eq!(
                store
                    .head(id, fixture.head.record)
                    .await
                    .unwrap()
                    .unwrap()
                    .revision,
                other.revision
            );
            connection
                .execute(
                    "UPDATE heads SET revision=?1 WHERE vault=?2 AND record=?3",
                    rusqlite::params![&fixture.head.revision, &id, &fixture.head.record],
                )
                .unwrap();
            let review = proof::prepare(&mut store, &mut fixture, proof::Mode::Full).await;
            assert_eq!(review.records, 2);
            fixture.engine.cancel_export(Some(review.token)).unwrap();
            assert_eq!(*proof::snapshot(&mut store, id).await, *before);
        });
}

#[test]
fn an_independent_write_after_serialization_prevents_artifact_release() {
    use confidex_app::{export, export_flow as flow};
    use confidex_storage::{Head, SqliteStore, Store, VaultId};
    use confidex_vault::{
        envelope::{self, EventKind, Options},
        resources::MAX_OPEN_MEMORY,
    };
    struct Change {
        path: std::path::PathBuf,
        vault: VaultId,
        expected: [u8; 32],
        next: Head,
        wire: Vec<u8>,
        tags: Vec<String>,
        wrote: bool,
        changed: bool,
    }
    impl flow::Control for Change {
        fn computing(&mut self, progress: export::Progress) -> bool {
            self.wrote |= progress.phase == export::Phase::Write;
            true
        }
        async fn checkpoint(&mut self, progress: export::Progress) -> bool {
            if self.wrote && !self.changed && progress.phase == export::Phase::Check {
                let mut other = SqliteStore::open(&self.path).unwrap();
                other
                    .append(
                        self.vault,
                        &self.next,
                        Some(self.expected),
                        &self.wire,
                        &self.tags,
                    )
                    .await
                    .unwrap();
                self.changed = true;
            }
            true
        }
    }
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("public-concurrent-export.sqlite");
            let mut store = SqliteStore::open(&path).unwrap();
            let mut fixture = proof::fixture(&mut store).await;
            let review = proof::prepare(&mut store, &mut fixture, proof::Mode::Full).await;
            let mut record = proof::content();
            record.entries[0]
                .value
                .insert("password".into(), "public change during export".into());
            let wire = envelope::seal(
                &record,
                fixture.vault.keys(),
                Options {
                    vault_id: fixture.created.info.id,
                    record_id: fixture.head.record,
                    parents: &[fixture.head.revision],
                    epoch: 3,
                    kind: EventKind::Content,
                },
                MAX_OPEN_MEMORY,
            )
            .unwrap();
            let revision = envelope::verify(&wire, fixture.vault.anchor(), None, MAX_OPEN_MEMORY)
                .unwrap()
                .id();
            let next = Head {
                record: fixture.head.record,
                revision,
            };
            let mut control = Change {
                path,
                vault: fixture.created.info.id,
                expected: fixture.head.revision,
                next: next.clone(),
                wire,
                tags: record.tags.clone(),
                wrote: false,
                changed: false,
            };
            assert_eq!(
                fixture
                    .engine
                    .generate_export(
                        &mut store,
                        review.token,
                        export::Consent::Lossless,
                        &mut control
                    )
                    .await
                    .err(),
                Some(flow::Error::Changed)
            );
            assert!(control.wrote && control.changed);
            assert_eq!(
                fixture.engine.export_chunk(review.token, 0).err(),
                Some(flow::Error::InvalidSession)
            );
            assert_eq!(
                store
                    .head(fixture.created.info.id, next.record)
                    .await
                    .unwrap()
                    .unwrap(),
                next
            );
            let before = proof::snapshot(&mut store, fixture.created.info.id).await;
            let fresh = proof::prepare(&mut store, &mut fixture, proof::Mode::Full).await;
            assert_eq!(
                fixture.engine.export_rows(fresh.token, 0).unwrap().items[0].head,
                next
            );
            fixture.engine.cancel_export(Some(fresh.token)).unwrap();
            assert_eq!(
                *proof::snapshot(&mut store, fixture.created.info.id).await,
                *before
            );
        });
}

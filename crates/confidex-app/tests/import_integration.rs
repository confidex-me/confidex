#![cfg(not(target_arch = "wasm32"))]
#[path = "import_integration/cases.rs"]
mod cases;
#[path = "import_integration/native_faults.rs"]
mod native_faults;
#[path = "import_integration/proof.rs"]
mod proof;

#[test]
fn kdbx_credential_modes_apply_reopen_backup_and_repeat_in_real_sqlite() {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            for case in cases::KDBX {
                let directory = tempfile::tempdir().unwrap();
                let path = directory.path().join("kdbx.sqlite");
                let mut store = confidex_storage::SqliteStore::open(&path).unwrap();
                let created = proof::first(&mut store, case).await;
                drop(store);
                let mut store = confidex_storage::SqliteStore::open(&path).unwrap();
                proof::reopened(&mut store, case, &created).await;
                println!(
                    "KDBX {}: {} selected of {}",
                    case.name, case.selected, case.total
                );
            }
        });
}

#[test]
fn kdbx_local_and_source_changes_require_explicit_decisions_in_real_sqlite() {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            for case in cases::KDBX {
                let directory = tempfile::tempdir().unwrap();
                let mut store = confidex_storage::SqliteStore::open(
                    &directory.path().join("kdbx-changes.sqlite"),
                )
                .unwrap();
                let created = proof::first(&mut store, case).await;
                proof::changes::run(&mut store, case, &created).await;
                println!("edited {}", case.name);
            }
        });
}

#[test]
fn rejected_sources_invalidate_preview_preserve_existing_data_and_allow_retry() {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("rejected.sqlite");
            let mut store = confidex_storage::SqliteStore::open(&path).unwrap();
            let (created, expected) = proof::rejected::first(&mut store).await;
            drop(store);
            let mut store = confidex_storage::SqliteStore::open(&path).unwrap();
            proof::rejected::reopened(&mut store, &created, &expected).await;
        });
}

#[test]
fn lock_and_destination_changes_invalidate_import_and_password_tokens() {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let directory = tempfile::tempdir().unwrap();
            let mut store =
                confidex_storage::SqliteStore::open(&directory.path().join("isolation.sqlite"))
                    .unwrap();
            proof::service::isolation(&mut store).await;
        });
}

#[test]
fn registered_formats_pass_the_serialized_import_protocol_and_reopen() {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            for case in proof::service::cases() {
                let directory = tempfile::tempdir().unwrap();
                let path = directory.path().join("service.sqlite");
                let mut store = confidex_storage::SqliteStore::open(&path).unwrap();
                let created = proof::service::first(&mut store, case).await;
                drop(store);
                let mut store = confidex_storage::SqliteStore::open(&path).unwrap();
                proof::service::reopened(&mut store, case, &created).await;
                println!("service {}", case.name);
            }
        });
}

#[test]
fn independent_process_creation_aborts_only_the_import_batch() {
    native_faults::concurrent();
}

#[test]
fn sqlite_full_preserves_existing_data_and_allows_reopen_retry() {
    native_faults::disk_full();
}

#[test]
fn damaged_imported_object_blocks_partial_index_results_and_recovers() {
    native_faults::index_recovery();
}

#[test]
fn published_formats_cancel_apply_reopen_backup_and_repeat_in_real_sqlite() {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            for case in cases::CASES {
                let directory = tempfile::tempdir().unwrap();
                let path = directory.path().join("public-integration.sqlite");
                let mut store = confidex_storage::SqliteStore::open(&path).unwrap();
                let created = proof::first(&mut store, case).await;
                drop(store);
                let mut store = confidex_storage::SqliteStore::open(&path).unwrap();
                proof::reopened(&mut store, case, &created).await;
                println!(
                    "completed {}: {} selected of {}, input_bytes={}",
                    case.name,
                    case.selected,
                    case.total,
                    case.input.len()
                );
            }
        });
}

#[test]
fn local_and_source_changes_require_explicit_decisions_in_real_sqlite() {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            for case in cases::CASES {
                let directory = tempfile::tempdir().unwrap();
                let mut store =
                    confidex_storage::SqliteStore::open(&directory.path().join("changes.sqlite"))
                        .unwrap();
                let created = proof::first(&mut store, case).await;
                proof::changes::run(&mut store, case, &created).await;
                println!("edited {}", case.name);
            }
        });
}

use crate::proof;
use confidex_app::import_apply::{Control, Phase, Progress};
use confidex_storage::{SqliteStore, VaultId};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
};
use zeroize::{Zeroize, Zeroizing};
const ACTOR: &str = "CONFIDEX_IMPORT_CONCURRENT_ACTOR";
#[derive(Serialize, Deserialize)]
struct Input {
    path: PathBuf,
    vault: VaultId,
    key: String,
    parent: u32,
}
impl Drop for Input {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
struct Writer {
    input: Input,
    fired: bool,
}
impl Control for Writer {
    async fn checkpoint(&mut self, progress: Progress) -> bool {
        if progress.phase == Phase::Commit {
            assert!(!self.fired);
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "independent_process_creation_aborts_only_the_import_batch",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(ACTOR, "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            let input = Zeroizing::new(serde_json::to_vec(&self.input).unwrap());
            child.stdin.take().unwrap().write_all(&input).unwrap();
            assert!(child.wait().unwrap().success());
            self.fired = true;
        }
        true
    }
}
pub fn concurrent() {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            if std::env::var_os(ACTOR).is_some() {
                let mut raw = Zeroizing::new(Vec::new());
                std::io::stdin()
                    .take(16 << 10)
                    .read_to_end(&mut raw)
                    .unwrap();
                let input: Input = serde_json::from_slice(&raw).unwrap();
                assert_ne!(std::process::id(), input.parent);
                let mut store = SqliteStore::open(&input.path).unwrap();
                proof::faults::write_concurrent(&mut store, input.vault, &input.key).await;
            } else {
                let directory = tempfile::tempdir().unwrap();
                let path = directory.path().join("concurrent.sqlite");
                let mut store = SqliteStore::open(&path).unwrap();
                let (mut engine, created) = proof::faults::setup(&mut store).await;
                let mut writer = Writer {
                    input: Input {
                        path,
                        vault: created.info.id,
                        key: created.key.clone(),
                        parent: std::process::id(),
                    },
                    fired: false,
                };
                proof::faults::concurrent(&mut engine, &mut store, &created, &mut writer).await;
                assert!(writer.fired);
            }
        });
}

pub fn disk_full() {
    use confidex_storage::Store;
    use rusqlite::{Connection, ErrorCode, params};
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("full.sqlite");
            // A shared pager lets the controller set the primary connection's ceiling.
            let uri = PathBuf::from(format!("file:{}?cache=shared", path.display()));
            let mut store = SqliteStore::open(&uri).unwrap();
            let (mut engine, created) = proof::faults::setup(&mut store).await;
            let id = created.info.id;
            proof::faults::write_concurrent(&mut store, id, &created.key).await;
            let controller = Connection::open(&uri).unwrap();
            // Remove free pages before the test sets the size limit.
            controller.execute_batch("VACUUM").unwrap();
            let pages: u32 = controller.pragma_query_value(None, "page_count", |r| r.get(0)).unwrap();
            let free: u32 = controller.pragma_query_value(None, "freelist_count", |r| r.get(0)).unwrap();
            let previous: u32 = controller.pragma_query_value(None, "max_page_count", |r| r.get(0)).unwrap();
            assert_eq!(free, 0);
            controller.pragma_update(None, "max_page_count", pages).unwrap();
            let tx = controller.unchecked_transaction().unwrap();
            let error = tx.execute(
                "INSERT INTO objects(vault,record,revision,wire) VALUES(?1,?2,?3,zeroblob(1048576))",
                params![id.as_slice(), [0xaau8;16].as_slice(), [0xbbu8;32].as_slice()],
            ).unwrap_err();
            assert!(matches!(error, rusqlite::Error::SqliteFailure(code, _) if code.code == ErrorCode::DiskFull));
            drop(tx);
            assert!(controller.is_autocommit());
            let input = proof::faults::large_input();
            let before = proof::faults::storage_failure(
                &mut engine, &mut store, &created, &input, confidex_storage::Error::Storage,
            ).await;
            drop(engine);
            drop(store);
            controller.pragma_update(None, "max_page_count", previous).unwrap();
            drop(controller);
            // Retry uses the ordinary file path after the test controller is closed.
            let mut store = SqliteStore::open(&path).unwrap();
            let after = proof::faults::retry(&mut store, &created, &before, &input).await;
            let controller = Connection::open(&path).unwrap();
            let page_size: u32 = controller.pragma_query_value(None, "page_size", |r| r.get(0)).unwrap();
            assert!(after.objects.iter().any(|object| object.wire.len() > page_size as usize));
            let grown: u32 = controller.pragma_query_value(None, "page_count", |r| r.get(0)).unwrap();
            assert!(grown > pages);
            let integrity: String = controller.pragma_query_value(None, "integrity_check", |r| r.get(0)).unwrap();
            assert_eq!(integrity, "ok");
            assert_eq!(store.snapshot(id).await.unwrap().heads, after.heads);
        });
}

pub fn index_recovery() {
    use confidex_storage::Store;
    use rusqlite::{Connection, params};
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("index.sqlite");
            let mut store = SqliteStore::open(&path).unwrap();
            let case = &crate::cases::CASES[0];
            let created = proof::first(&mut store, case).await;
            let id = created.info.id;
            let before = store.snapshot(id).await.unwrap();
            assert_eq!(before.heads.len(), 3);
            let target = before.heads.last().unwrap();
            let original = &before
                .objects
                .iter()
                .find(|object| object.head == *target)
                .unwrap()
                .wire;
            let mut engine = proof::index::open(&mut store, &created).await;
            let mut damaged = original.clone();
            *damaged.last_mut().unwrap() ^= 1;
            let controller = Connection::open(&path).unwrap();
            assert_eq!(
                controller
                    .execute(
                        "UPDATE objects SET wire=?3 WHERE vault=?1 AND revision=?2",
                        params![id.as_slice(), target.revision.as_slice(), &damaged],
                    )
                    .unwrap(),
                1
            );
            proof::index::failed(&mut engine, &mut store).await;
            assert_eq!(
                controller
                    .execute(
                        "UPDATE objects SET wire=?3 WHERE vault=?1 AND revision=?2",
                        params![id.as_slice(), target.revision.as_slice(), original],
                    )
                    .unwrap(),
                1
            );
            proof::index::recovered(&mut engine, &mut store, &created, &before).await;
            drop(engine);
            drop(controller);
            drop(store);
            let mut store = SqliteStore::open(&path).unwrap();
            proof::reopened(&mut store, case, &created).await;
        });
}

#![cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
use confidex_storage::*;

const VAULT: VaultId = [1; 16];
const RECORD: RecordId = [2; 16];

fn object(n: u16) -> StoredObject {
    let mut revision = [0; 32];
    revision[..2].copy_from_slice(&n.to_be_bytes());
    StoredObject {
        head: Head {
            record: RECORD,
            revision,
        },
        wire: n.to_be_bytes().to_vec(),
        tags: vec!["branch".into()],
    }
}

#[test]
fn a_commit_cannot_replace_one_tip_twice_or_repeat_the_same_change() {
    let mut commit = SyncCommit {
        previous: None,
        current: vec![1],
        objects: vec![],
        heads: vec![
            HeadChange {
                head: object(2).head,
                expected: Some(object(1).head.revision),
            },
            HeadChange {
                head: object(3).head,
                expected: Some(object(1).head.revision),
            },
        ],
    };
    assert_eq!(commit.validate(), Err(Error::Invalid));
    commit.heads[1].expected = Some(object(4).head.revision);
    assert_eq!(commit.validate(), Ok(()));
    commit.heads[1].head = commit.heads[0].head.clone();
    assert_eq!(commit.validate(), Ok(()));
    commit.heads[1].expected = commit.heads[0].expected;
    assert_eq!(commit.validate(), Err(Error::Invalid));
    commit.heads[1].head = object(3).head;
    commit.heads[0].expected = None;
    commit.heads[1].expected = None;
    assert_eq!(commit.validate(), Ok(()));
    commit.heads[1].head = commit.heads[0].head.clone();
    assert_eq!(commit.validate(), Err(Error::Invalid));
}

#[test]
fn branches_page_advance_and_restore_without_losing_siblings() {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("source.sqlite");
            let mut store = SqliteStore::open(&path).unwrap();
            store
                .create(&StoredVault {
                    info: VaultInfo {
                        id: VAULT,
                        name: "Branches".into(),
                    },
                    lock: vec![1],
                })
                .await
                .unwrap();
            let mut checkpoint = None;
            for batch in 0..3u16 {
                let objects: Vec<_> = (batch * 90..(batch + 1) * 90).map(object).collect();
                let heads = objects
                    .iter()
                    .map(|o| HeadChange {
                        head: o.head.clone(),
                        expected: None,
                    })
                    .collect();
                let current = batch.to_be_bytes().to_vec();
                store
                    .publish_branches(
                        VAULT,
                        &SyncCommit {
                            previous: checkpoint,
                            current: current.clone(),
                            objects,
                            heads,
                        },
                    )
                    .await
                    .unwrap();
                checkpoint = Some(current);
            }
            let mut heads = Vec::new();
            loop {
                let page = store
                    .branch_heads(VAULT, heads.last(), Some("branch"))
                    .await
                    .unwrap();
                if page.is_empty() {
                    break;
                }
                heads.extend(page);
            }
            assert_eq!(heads, (0..270).map(|n| object(n).head).collect::<Vec<_>>());
            assert_eq!(store.head(VAULT, RECORD).await, Err(Error::Conflict));
            assert_eq!(store.heads(VAULT, None).await, Err(Error::Conflict));
            let mut other = SqliteStore::open(&path).unwrap();
            let next = object(900);
            let commit = SyncCommit {
                previous: checkpoint.clone(),
                current: vec![4],
                objects: vec![next],
                heads: vec![HeadChange {
                    head: object(900).head,
                    expected: Some(heads[0].revision),
                }],
            };
            store.publish_branches(VAULT, &commit).await.unwrap();
            let losing = SyncCommit {
                previous: Some(vec![4]),
                current: vec![5],
                objects: vec![object(901)],
                heads: vec![HeadChange {
                    head: object(901).head,
                    expected: Some(heads[0].revision),
                }],
            };
            assert_eq!(
                other.publish_branches(VAULT, &losing).await,
                Err(Error::Conflict)
            );
            assert_eq!(
                other.object(VAULT, object(901).head.revision).await,
                Err(Error::NotFound)
            );
            assert_eq!(other.sync_state(VAULT).await.unwrap(), Some(vec![4]));
            assert_eq!(
                other.publish_branches(VAULT, &commit).await,
                Err(Error::Conflict)
            );
            store
                .publish_branches(
                    VAULT,
                    &SyncCommit {
                        previous: Some(vec![4]),
                        current: vec![6],
                        objects: vec![object(902)],
                        heads: vec![
                            HeadChange {
                                head: object(902).head,
                                expected: Some(heads[1].revision),
                            },
                            HeadChange {
                                head: object(902).head,
                                expected: Some(heads[2].revision),
                            },
                        ],
                    },
                )
                .await
                .unwrap();
            let snapshot = store.snapshot(VAULT).await.unwrap();
            assert_eq!(snapshot.heads.len(), 269);
            assert_eq!(snapshot.objects.len(), 272);
            assert!(!snapshot.heads.contains(&heads[0]));
            assert!(!snapshot.heads.contains(&heads[1]));
            assert!(!snapshot.heads.contains(&heads[2]));
            assert!(snapshot.heads.contains(&object(900).head));
            assert!(snapshot.heads.contains(&object(902).head));
            assert_eq!(
                store.object(VAULT, heads[0].revision).await.unwrap(),
                object(0).wire
            );
            let mut restored = SqliteStore::open(&dir.path().join("restored.sqlite")).unwrap();
            restored.restore(&snapshot).await.unwrap();
            assert_eq!(
                restored.snapshot(VAULT).await.unwrap().heads,
                snapshot.heads
            );
            drop(store);
            let mut reopened = SqliteStore::open(&path).unwrap();
            assert_eq!(
                reopened.snapshot(VAULT).await.unwrap().heads,
                snapshot.heads
            );
            reopened.clear_records(VAULT).await.unwrap();
            assert!(
                reopened
                    .branch_heads(VAULT, None, None)
                    .await
                    .unwrap()
                    .is_empty()
            );
        });
}

#[test]
fn migration_preserves_v4_objects_heads_tags_and_checkpoint() {
    tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.sqlite");
        let mut store = SqliteStore::open(&path).unwrap();
        store.create(&StoredVault {
            info: VaultInfo { id: VAULT, name: "Legacy".into() }, lock: vec![1],
        }).await.unwrap();
        let first = object(7);
        store.append(VAULT, &first.head, None, &first.wire, &first.tags).await.unwrap();
        store.sync_commit(VAULT, &SyncCommit {
            previous: None, current: vec![9], objects: vec![], heads: vec![],
        }).await.unwrap();
        drop(store);
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("BEGIN IMMEDIATE;
            ALTER TABLE heads RENAME TO source_heads;
            CREATE TABLE heads(vault BLOB NOT NULL,record BLOB NOT NULL,revision BLOB NOT NULL,
                PRIMARY KEY(vault,record), FOREIGN KEY(vault,revision) REFERENCES objects(vault,revision));
            INSERT INTO heads SELECT * FROM source_heads;
            DROP TABLE source_heads; PRAGMA user_version=4; COMMIT;").unwrap();
        drop(db);
        let mut store = SqliteStore::open(&path).unwrap();
        assert_eq!(store.head(VAULT, RECORD).await.unwrap(), Some(first.head.clone()));
        assert_eq!(store.branch_heads(VAULT, None, Some("branch")).await.unwrap(), vec![first.head]);
        assert_eq!(store.sync_state(VAULT).await.unwrap(), Some(vec![9]));
        assert_eq!(store.object(VAULT, object(7).head.revision).await.unwrap(), first.wire);
        let db = rusqlite::Connection::open(&path).unwrap();
        assert_eq!(db.pragma_query_value(None,"user_version",|row|row.get::<_,u32>(0)).unwrap(),5);
    });
}

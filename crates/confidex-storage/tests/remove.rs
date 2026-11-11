#![cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
use confidex_storage::{Error, Head, SqliteStore, Store, StoredVault, SyncCommit, VaultInfo};

#[test]
fn removal_is_atomic_isolated_and_rejects_stale_writers() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vaults.sqlite");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut store = SqliteStore::open(&path).unwrap();
        let mut other_process = SqliteStore::open(&path).unwrap();
        let head = Head { record: [3; 16], revision: [4; 32] };
        for id in [[1; 16], [2; 16]] {
            store.create(&StoredVault {info: VaultInfo {id,name: "Public fixture".into()},lock:vec![0]}).await.unwrap();
            store.append(id, &head, None, &[7], &["private-tag-fixture".into()]).await.unwrap();
            store.sync_commit(id, &SyncCommit {previous:None,current:vec![8],objects:vec![],heads:vec![]}).await.unwrap();
        }
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("CREATE TRIGGER refuse_removal BEFORE DELETE ON vaults BEGIN SELECT RAISE(ABORT, 'fixture'); END;").unwrap();
        assert_eq!(store.remove([1;16]).await, Err(Error::Storage));
        assert_eq!(store.snapshot([1;16]).await.unwrap().objects.len(),1);
        assert_eq!(store.tagged_heads([1;16], "private-tag-fixture", None).await.unwrap().len(),1);
        assert_eq!(store.sync_state([1;16]).await.unwrap(),Some(vec![8]));
        db.execute_batch("DROP TRIGGER refuse_removal").unwrap();
        store.remove([1;16]).await.unwrap();
        store.remove([1;16]).await.unwrap();
        assert!(matches!(store.vault([1;16]).await,Err(Error::NotFound)));
        assert!(store.heads([1;16],None).await.unwrap().is_empty());
        assert!(store.tagged_heads([1;16],"private-tag-fixture",None).await.unwrap().is_empty());
        assert_eq!(store.object([1;16],[4;32]).await,Err(Error::NotFound));
        assert_eq!(store.sync_state([1;16]).await.unwrap(),None);
        assert_eq!(store.vaults().await.unwrap().len(),1);
        assert_eq!(store.snapshot([2;16]).await.unwrap().objects.len(),1);
        assert_eq!(store.sync_state([2;16]).await.unwrap(),Some(vec![8]));
        assert_eq!(other_process.append([1;16],&head,None,&[7],&[]).await,Err(Error::NotFound));
        assert_eq!(other_process.sync_commit([1;16],&SyncCommit {previous:None,current:vec![9],objects:vec![],heads:vec![]}).await,Err(Error::NotFound));
        for (table, column) in [("vaults","id"),("objects","vault"),("heads","vault"),("record_tags","vault"),("sync_state","vault")] {
            let count:i64=db.query_row(&format!("SELECT count(*) FROM {table} WHERE {column}=?1"),[[1u8;16].as_slice()],|r|r.get(0)).unwrap();
            assert_eq!(count,0,"{table}");
        }
    });
}

#[test]
fn pending_removal_survives_reopening_and_blocks_legacy_sql() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("pending.sqlite");
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let mut store = SqliteStore::open(&path).unwrap();
            let vault = [9; 16];
            store
                .create(&StoredVault {
                    info: VaultInfo {
                        id: vault,
                        name: "Public pending fixture".into(),
                    },
                    lock: vec![1],
                })
                .await
                .unwrap();
            let legacy = rusqlite::Connection::open(&path).unwrap();
            store.clear_records(vault).await.unwrap();
            let mut reopened = SqliteStore::open(&path).unwrap();
            assert_eq!(reopened.vaults().await.unwrap().len(), 1);
            assert!(matches!(reopened.vault(vault).await, Err(Error::Removing)));
            let head = Head {
                record: [3; 16],
                revision: [4; 32],
            };
            assert_eq!(
                reopened.append(vault, &head, None, &[7], &[]).await,
                Err(Error::Removing)
            );
            assert_eq!(
                reopened
                    .sync_commit(
                        vault,
                        &SyncCommit {
                            previous: None,
                            current: vec![8],
                            objects: vec![],
                            heads: vec![]
                        }
                    )
                    .await,
                Err(Error::Removing)
            );
            assert!(
                legacy
                    .execute(
                        "INSERT INTO objects(vault,record,revision,wire) VALUES(?1,?2,?3,?4)",
                        rusqlite::params![
                            vault.as_slice(),
                            head.record.as_slice(),
                            head.revision.as_slice(),
                            [7u8].as_slice()
                        ]
                    )
                    .is_err()
            );
            store.remove(vault).await.unwrap();
            assert!(reopened.vaults().await.unwrap().is_empty());
        });
}

#[test]
fn schema_three_upgrades_without_changing_existing_data() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("legacy.sqlite");
    let legacy = rusqlite::Connection::open(&path).unwrap();
    legacy.execute_batch("CREATE TABLE vaults(id BLOB PRIMARY KEY,name TEXT NOT NULL,lock BLOB NOT NULL);
        CREATE TABLE objects(vault BLOB,record BLOB,revision BLOB,wire BLOB,PRIMARY KEY(vault,revision));
        CREATE TABLE heads(vault BLOB,record BLOB,revision BLOB,PRIMARY KEY(vault,record));
        CREATE TABLE sync_state(vault BLOB PRIMARY KEY,checkpoint BLOB);
        CREATE TABLE record_tags(vault BLOB,record BLOB,revision BLOB,tag TEXT,PRIMARY KEY(vault,revision,tag));
        PRAGMA user_version=3;").unwrap();
    let vault = [1u8; 16];
    let record = [2u8; 16];
    let revision = [3u8; 32];
    legacy
        .execute(
            "INSERT INTO vaults VALUES(?1,'Legacy fixture',?2)",
            rusqlite::params![vault.as_slice(), [5u8].as_slice()],
        )
        .unwrap();
    legacy
        .execute(
            "INSERT INTO objects VALUES(?1,?2,?3,?4)",
            rusqlite::params![
                vault.as_slice(),
                record.as_slice(),
                revision.as_slice(),
                [7u8].as_slice()
            ],
        )
        .unwrap();
    legacy
        .execute(
            "INSERT INTO heads VALUES(?1,?2,?3)",
            rusqlite::params![vault.as_slice(), record.as_slice(), revision.as_slice()],
        )
        .unwrap();
    legacy
        .execute(
            "INSERT INTO record_tags VALUES(?1,?2,?3,'local-tag')",
            rusqlite::params![vault.as_slice(), record.as_slice(), revision.as_slice()],
        )
        .unwrap();
    legacy
        .execute(
            "INSERT INTO sync_state VALUES(?1,?2)",
            rusqlite::params![vault.as_slice(), [9u8].as_slice()],
        )
        .unwrap();
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let mut store = SqliteStore::open(&path).unwrap();
            let snapshot = store.snapshot(vault).await.unwrap();
            assert_eq!(snapshot.vault.info.name, "Legacy fixture");
            assert_eq!(snapshot.vault.lock, [5]);
            assert_eq!(snapshot.objects.len(), 1);
            assert_eq!(snapshot.objects[0].wire, [7]);
            assert_eq!(snapshot.heads[0].revision, revision);
            assert_eq!(store.sync_state(vault).await.unwrap(), Some(vec![9]));
            assert_eq!(
                store
                    .tagged_heads(vault, "local-tag", None)
                    .await
                    .unwrap()
                    .len(),
                1
            );
        });
    let version: u32 = legacy
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(version, 5);
}

#![cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
use confidex_storage::{
    BatchCommit, Error, Head, HeadChange, MAX_BATCH_BASE_HEADS, MAX_OBJECT, SqliteStore, Store,
    StoredObject, StoredVault, SyncCommit, VaultInfo,
};
use rusqlite::Connection;

const VAULT: [u8; 16] = [1; 16];
fn head(id: u32, version: u8) -> Head {
    let mut record = [0; 16];
    record[..4].copy_from_slice(&id.to_be_bytes());
    let mut revision = [0; 32];
    revision[..16].copy_from_slice(&record);
    revision[31] = version;
    Head { record, revision }
}
fn batch(previous: Vec<Head>, ids: &[u32]) -> BatchCommit {
    let mut objects = Vec::new();
    let mut heads = Vec::new();
    for &id in ids {
        let head = head(id, 1);
        let expected = previous
            .iter()
            .find(|h| h.record == head.record)
            .map(|h| h.revision);
        objects.push(StoredObject {
            head: head.clone(),
            wire: vec![id as u8; 32],
            tags: vec!["fixture".into()],
        });
        heads.push(HeadChange { head, expected });
    }
    BatchCommit {
        previous,
        objects,
        heads,
    }
}
async fn create(store: &mut SqliteStore) {
    store
        .create(&StoredVault {
            info: VaultInfo {
                id: VAULT,
                name: "Public batch fixture".into(),
            },
            lock: vec![1],
        })
        .await
        .unwrap();
}
async fn all_heads(store: &mut SqliteStore) -> Vec<Head> {
    let mut all = Vec::new();
    let mut after = None;
    loop {
        let page = store.heads(VAULT, after).await.unwrap();
        if page.is_empty() {
            return all;
        }
        after = page.last().map(|h| h.record);
        all.extend(page);
    }
}
fn run(f: impl Future<Output = ()>) {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f);
}
#[test]
fn branch_batches_update_selected_tips_and_compare_the_complete_catalog() {
    run(async {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("branches.sqlite");
        let mut store = SqliteStore::open(&path).unwrap();
        create(&mut store).await;
        let old = vec![head(1, 1), head(1, 2), head(1, 3)];
        store
            .publish_branches(
                VAULT,
                &SyncCommit {
                    previous: None,
                    current: vec![7],
                    objects: old
                        .iter()
                        .map(|h| StoredObject {
                            head: h.clone(),
                            wire: h.revision.to_vec(),
                            tags: vec![],
                        })
                        .collect(),
                    heads: old
                        .iter()
                        .map(|h| HeadChange {
                            head: h.clone(),
                            expected: None,
                        })
                        .collect(),
                },
            )
            .await
            .unwrap();
        let commit = BatchCommit {
            previous: old.clone(),
            objects: [4, 5]
                .into_iter()
                .map(|n| StoredObject {
                    head: head(1, n),
                    wire: vec![n; 32],
                    tags: vec!["public".into()],
                })
                .collect(),
            heads: [4, 5]
                .into_iter()
                .enumerate()
                .map(|(i, n)| HeadChange {
                    head: head(1, n),
                    expected: Some(old[i].revision),
                })
                .collect(),
        };
        store.batch_commit(VAULT, &commit).await.unwrap();
        assert_eq!(
            store.branch_heads(VAULT, None, None).await.unwrap(),
            vec![head(1, 3), head(1, 4), head(1, 5)]
        );
        assert_eq!(store.sync_state(VAULT).await.unwrap(), Some(vec![7]));
        for h in &old {
            assert_eq!(store.object(VAULT, h.revision).await.unwrap(), h.revision);
        }
        assert_eq!(
            store.batch_commit(VAULT, &commit).await,
            Err(Error::Conflict)
        );
        let mut stale = batch(store.branch_heads(VAULT, None, None).await.unwrap(), &[9]);
        let mut peer = SqliteStore::open(&path).unwrap();
        peer.publish_branches(
            VAULT,
            &SyncCommit {
                previous: Some(vec![7]),
                current: vec![8],
                objects: vec![StoredObject {
                    head: head(1, 6),
                    wire: vec![6; 32],
                    tags: vec![],
                }],
                heads: vec![HeadChange {
                    head: head(1, 6),
                    expected: None,
                }],
            },
        )
        .await
        .unwrap();
        assert_eq!(
            store.batch_commit(VAULT, &stale).await,
            Err(Error::Conflict)
        );
        assert_eq!(
            store.object(VAULT, head(9, 1).revision).await,
            Err(Error::NotFound)
        );
        stale.previous = store.branch_heads(VAULT, None, None).await.unwrap();
        store.batch_commit(VAULT, &stale).await.unwrap();
        let mut invalid = batch(store.branch_heads(VAULT, None, None).await.unwrap(), &[1]);
        invalid.heads[0].expected = None;
        assert_eq!(
            store.batch_commit(VAULT, &invalid).await,
            Err(Error::Invalid)
        );
    });
}
#[test]
fn batch_rolls_back_and_compares_the_whole_catalog() {
    run(async {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.sqlite");
        let mut store = SqliteStore::open(&path).unwrap();
        create(&mut store).await;
        let old = head(1, 0);
        store
            .append(VAULT, &old, None, b"public old wire", &[])
            .await
            .unwrap();
        store
            .sync_commit(
                VAULT,
                &SyncCommit {
                    previous: None,
                    current: vec![7],
                    objects: vec![],
                    heads: vec![],
                },
            )
            .await
            .unwrap();
        let commit = batch(vec![old.clone()], &[2, 3]);
        let injector = Connection::open(&path).unwrap();
        let record = commit.heads[1]
            .head
            .record
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>();
        injector.execute_batch(&format!("CREATE TRIGGER fail_batch BEFORE INSERT ON heads WHEN hex(NEW.record)='{record}' BEGIN SELECT RAISE(ABORT,'public failure fixture'); END;")).unwrap();
        assert_eq!(
            store.batch_commit(VAULT, &commit).await,
            Err(Error::Storage)
        );
        assert_eq!(all_heads(&mut store).await, vec![old.clone()]);
        for object in &commit.objects {
            assert_eq!(
                store.object(VAULT, object.head.revision).await,
                Err(Error::NotFound)
            );
        }
        injector.execute_batch("DROP TRIGGER fail_batch;").unwrap();
        store.batch_commit(VAULT, &commit).await.unwrap();
        assert_eq!(all_heads(&mut store).await.len(), 3);
        assert_eq!(store.sync_state(VAULT).await.unwrap(), Some(vec![7]));
        assert_eq!(
            store.batch_commit(VAULT, &commit).await,
            Err(Error::Conflict)
        );
        let stale = batch(all_heads(&mut store).await, &[4]);
        let mut concurrent = SqliteStore::open(&path).unwrap();
        concurrent
            .append(VAULT, &head(9, 0), None, b"public concurrent wire", &[])
            .await
            .unwrap();
        assert_eq!(
            store.batch_commit(VAULT, &stale).await,
            Err(Error::Conflict)
        );
        assert_eq!(store.head(VAULT, head(4, 1).record).await.unwrap(), None);
        let previous = all_heads(&mut store).await;
        let mut update = batch(previous, &[1]);
        update.objects[0].wire = b"public updated wire".to_vec();
        store.batch_commit(VAULT, &update).await.unwrap();
        assert_eq!(
            store.head(VAULT, old.record).await.unwrap(),
            Some(head(1, 1))
        );
        assert_eq!(
            store.object(VAULT, old.revision).await.unwrap(),
            b"public old wire"
        );
        let mut collision = batch(all_heads(&mut store).await, &[8]);
        collision.objects[0].head.revision = old.revision;
        collision.heads[0].head.revision = old.revision;
        assert_eq!(
            store.batch_commit(VAULT, &collision).await,
            Err(Error::Conflict)
        );
        assert_eq!(store.head(VAULT, head(8, 1).record).await.unwrap(), None);
        store.clear_records(VAULT).await.unwrap();
        assert_eq!(
            store.batch_commit(VAULT, &batch(vec![], &[1])).await,
            Err(Error::Removing)
        );
    });
}
#[test]
fn batch_admission_rejects_ambiguous_bindings_and_limits() {
    let mut commit = batch(vec![], &[1, 2]);
    commit.heads[1].head.record = commit.heads[0].head.record;
    assert_eq!(commit.validate(), Err(Error::Invalid));
    let mut commit = batch(vec![], &[1]);
    commit.heads[0].expected = Some([9; 32]);
    assert_eq!(commit.validate(), Err(Error::Invalid));
    let mut commit = batch(vec![], &[1]);
    commit.objects[0].wire = vec![0; MAX_OBJECT + 1];
    assert_eq!(commit.validate(), Err(Error::Limit));
    let mut commit = batch(vec![], &[1]);
    commit.objects[0].tags = vec!["same".into(), "same".into()];
    assert_eq!(commit.validate(), Err(Error::Limit));
    let mut unicode = batch(vec![], &[1]);
    unicode.objects[0].tags = vec!["\u{e000}".into(), "\u{10000}".into()];
    assert!(unicode.validate().is_ok());
    unicode.objects[0].tags.reverse();
    assert_eq!(unicode.validate(), Err(Error::Limit));
    let mut large = batch(vec![], &[1, 2, 3, 4, 5, 6, 7, 8, 9]);
    for object in &mut large.objects {
        object.wire = vec![0; MAX_OBJECT];
    }
    assert_eq!(large.validate(), Err(Error::Limit));
    let mut commit = batch(vec![], &[1]);
    commit.previous = vec![head(2, 0), head(1, 0)];
    assert_eq!(commit.validate(), Err(Error::Invalid));
    let mut commit = batch(vec![], &[]);
    commit.previous = vec![head(1, 0); MAX_BATCH_BASE_HEADS + 1];
    assert_eq!(commit.validate(), Err(Error::Limit));
}
#[test]
fn ten_thousand_records_publish_as_one_batch() {
    run(async {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SqliteStore::open(&dir.path().join("store.sqlite")).unwrap();
        create(&mut store).await;
        let ids: Vec<_> = (1..=10000).collect();
        let commit = batch(vec![], &ids);
        let start = std::time::Instant::now();
        store.batch_commit(VAULT, &commit).await.unwrap();
        eprintln!("SQLite opaque 10k batch: {:?}", start.elapsed());
        assert_eq!(all_heads(&mut store).await.len(), 10000);
        assert_eq!(
            store.object(VAULT, head(10000, 1).revision).await.unwrap(),
            vec![10000u32 as u8; 32]
        );
        assert_eq!(
            store
                .tagged_heads(VAULT, "fixture", None)
                .await
                .unwrap()
                .len(),
            128
        );
        assert_eq!(store.sync_state(VAULT).await.unwrap(), None);
    });
}

#![cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
use confidex_storage::*;

#[test]
fn tag_lookup_pages_all_heads_and_excludes_replaced_or_deleted_tags() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tags.sqlite");
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let mut store = SqliteStore::open(&path).unwrap();
            let vault = [1; 16];
            store
                .create(&StoredVault {
                    info: VaultInfo {
                        id: vault,
                        name: "Tags".into(),
                    },
                    lock: vec![1],
                })
                .await
                .unwrap();
            for n in 0u16..260 {
                let mut record = [0; 16];
                record[..2].copy_from_slice(&n.to_be_bytes());
                let mut revision = [0; 32];
                revision[..2].copy_from_slice(&n.to_be_bytes());
                store
                    .append(
                        vault,
                        &Head { record, revision },
                        None,
                        &[1],
                        &["tag".into()],
                    )
                    .await
                    .unwrap();
            }
            let first = store.tagged_heads(vault, "tag", None).await.unwrap();
            assert_eq!(first.len(), 128);
            let second = store
                .tagged_heads(vault, "tag", Some(first[127].record))
                .await
                .unwrap();
            assert_eq!(second.len(), 128);
            let last = store
                .tagged_heads(vault, "tag", Some(second[127].record))
                .await
                .unwrap();
            assert_eq!(last.len(), 4);
            assert!(first[127].record < second[0].record && second[127].record < last[0].record);
            assert!(
                store
                    .tagged_heads([2; 16], "tag", None)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(
                store
                    .tagged_heads(vault, "Tag", None)
                    .await
                    .unwrap()
                    .is_empty()
            );
            let old = &last[3];
            let next = Head {
                record: old.record,
                revision: [255; 32],
            };
            assert_eq!(
                store
                    .append(vault, &next, Some([9; 32]), &[2], &["losing".into()])
                    .await,
                Err(Error::Conflict)
            );
            assert!(
                store
                    .tagged_heads(vault, "losing", None)
                    .await
                    .unwrap()
                    .is_empty()
            );
            store
                .append(vault, &next, Some(old.revision), &[2], &[])
                .await
                .unwrap();
            drop(store);
            let mut store = SqliteStore::open(&path).unwrap();
            assert_eq!(
                store
                    .tagged_heads(vault, "tag", Some(second[127].record))
                    .await
                    .unwrap()
                    .len(),
                3
            );
            assert!(store.head(vault, old.record).await.unwrap().unwrap() == next);
        });
}

#[test]
fn sync_checkpoints_and_heads_commit_together_across_connections() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.sqlite");
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let mut a = SqliteStore::open(&path).unwrap();
            let mut b = SqliteStore::open(&path).unwrap();
            a.create(&StoredVault {
                info: VaultInfo {
                    id: [1; 16],
                    name: "Fixture".into(),
                },
                lock: vec![1],
            })
            .await
            .unwrap();
            let first = Head {
                record: [2; 16],
                revision: [3; 32],
            };
            let commit = SyncCommit {
                previous: None,
                current: b"first".to_vec(),
                objects: vec![StoredObject {
                    head: first.clone(),
                    wire: vec![4],
                    tags: vec!["first".into()],
                }],
                heads: vec![HeadChange {
                    head: first.clone(),
                    expected: None,
                }],
            };
            a.sync_commit([1; 16], &commit).await.unwrap();
            assert!(matches!(
                b.sync_commit([1; 16], &commit).await,
                Err(Error::Conflict)
            ));
            let next = Head {
                record: [2; 16],
                revision: [5; 32],
            };
            let invalid = SyncCommit {
                previous: Some(b"first".to_vec()),
                current: b"second".to_vec(),
                objects: vec![StoredObject {
                    head: next.clone(),
                    wire: vec![6],
                    tags: vec!["second".into()],
                }],
                heads: vec![HeadChange {
                    head: next.clone(),
                    expected: Some([0; 32]),
                }],
            };
            assert!(matches!(
                b.sync_commit([1; 16], &invalid).await,
                Err(Error::Conflict)
            ));
            assert_eq!(a.sync_state([1; 16]).await.unwrap().unwrap(), b"first");
            assert_eq!(
                a.head([1; 16], [2; 16]).await.unwrap().unwrap().revision,
                first.revision
            );
            assert!(matches!(
                a.object([1; 16], next.revision).await,
                Err(Error::NotFound)
            ));
            assert_eq!(
                a.tagged_heads([1; 16], "first", None).await.unwrap().len(),
                1
            );
            assert!(
                a.tagged_heads([1; 16], "second", None)
                    .await
                    .unwrap()
                    .is_empty()
            );
            let valid = SyncCommit {
                heads: vec![HeadChange {
                    head: next,
                    expected: Some(first.revision),
                }],
                ..invalid
            };
            b.sync_commit([1; 16], &valid).await.unwrap();
            assert_eq!(a.sync_state([1; 16]).await.unwrap().unwrap(), b"second");
            assert_eq!(a.object([1; 16], [5; 32]).await.unwrap(), [6]);
            drop(a);
            let mut a = SqliteStore::open(&path).unwrap();
            assert!(
                a.tagged_heads([1; 16], "first", None)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                a.tagged_heads([1; 16], "second", None).await.unwrap().len(),
                1
            );
        });
}

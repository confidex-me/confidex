#![cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
use confidex_storage::*;

#[test]
fn renaming_changes_only_the_local_name_and_checks_concurrent_writers() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("rename.sqlite");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut store = SqliteStore::open(&path).unwrap();
        let mut second = SqliteStore::open(&path).unwrap();
        let vault = [1; 16];
        for id in [vault, [2; 16]] {
            store
                .create(&StoredVault {
                    info: VaultInfo {
                        id,
                        name: "Original".into(),
                    },
                    lock: vec![5],
                })
                .await
                .unwrap();
        }
        let head = Head {
            record: [3; 16],
            revision: [4; 32],
        };
        store
            .append(vault, &head, None, &[7], &["tag".into()])
            .await
            .unwrap();
        store
            .sync_commit(
                vault,
                &SyncCommit {
                    previous: None,
                    current: vec![8],
                    objects: vec![],
                    heads: vec![],
                },
            )
            .await
            .unwrap();
        let name = format!("{}ab", "雪".repeat(42));
        assert_eq!(name.len(), 128);
        store.rename(vault, "Original", &name).await.unwrap();
        assert_eq!(
            second.rename(vault, "Original", "Stale").await,
            Err(Error::Conflict)
        );
        assert_eq!(store.rename(vault, &name, "").await, Err(Error::Invalid));
        assert_eq!(
            store.rename(vault, &name, &"雪".repeat(43)).await,
            Err(Error::Invalid)
        );
        let snapshot = second.snapshot(vault).await.unwrap();
        assert_eq!(snapshot.vault.info.id, vault);
        assert_eq!(snapshot.vault.info.name, name);
        assert_eq!(snapshot.vault.lock, [5]);
        assert!(snapshot.heads == [head.clone()]);
        assert_eq!(snapshot.objects.len(), 1);
        assert_eq!(snapshot.objects[0].wire, [7]);
        assert!(second.tagged_heads(vault, "tag", None).await.unwrap() == [head]);
        assert_eq!(second.sync_state(vault).await.unwrap(), Some(vec![8]));
        assert_eq!(store.vault([2; 16]).await.unwrap().info.name, "Original");
        drop(store);
        assert_eq!(
            SqliteStore::open(&path)
                .unwrap()
                .vault(vault)
                .await
                .unwrap()
                .info
                .name,
            name
        );
        second.clear_records(vault).await.unwrap();
        assert_eq!(
            second.rename(vault, &name, "Blocked").await,
            Err(Error::Removing)
        );
        second.remove(vault).await.unwrap();
        assert_eq!(
            second.rename(vault, &name, "Missing").await,
            Err(Error::NotFound)
        );
    });
}

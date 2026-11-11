#![cfg(not(target_arch = "wasm32"))]
use confidex_app::{self as app, Command, DeviceKeys, Engine, Error, Output, Request};
use confidex_storage::{Snapshot, SqliteStore, Store};
use std::{
    collections::BTreeMap,
    io::{Cursor, Read, Write},
};
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};
const PASSWORD: &str = "public-backup-test-password";
const PRIVATE: &str = "private-backup-fixture-value";
#[derive(Default)]
struct Keys(BTreeMap<[u8; 16], String>);
impl DeviceKeys for Keys {
    async fn remove(&mut self, id: [u8; 16]) -> bool {
        if let Some(mut key) = self.0.remove(&id) {
            zeroize::Zeroize::zeroize(&mut key);
        }
        true
    }

    async fn load(&mut self, id: [u8; 16]) -> Option<String> {
        self.0.get(&id).cloned()
    }
    async fn save(&mut self, id: [u8; 16], key: &str) -> bool {
        self.0.insert(id, key.into());
        true
    }
}
async fn run(
    engine: &mut Engine,
    store: &mut SqliteStore,
    keys: &mut Keys,
    command: Command,
) -> Result<Output, Error> {
    engine
        .execute(
            store,
            keys,
            &mut Request {
                generation: 1,
                command,
            },
        )
        .await
        .result
}
fn rewrite(bytes: &[u8], mut change: impl FnMut(&str, &mut Vec<u8>) -> bool) -> Vec<u8> {
    let mut input = ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    for i in 0..input.len() {
        let mut file = input.by_index(i).unwrap();
        let name = file.name().unwrap().into_owned();
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();
        if change(&name, &mut data) {
            zip.start_file(name, SimpleFileOptions::default()).unwrap();
            zip.write_all(&data).unwrap();
        }
    }
    zip.finish().unwrap().into_inner()
}
fn same(a: &Snapshot, b: &Snapshot) {
    assert_eq!(a.vault.info.id, b.vault.info.id);
    assert_eq!(a.vault.lock, b.vault.lock);
    assert!(a.heads == b.heads);
    assert_eq!(a.objects.len(), b.objects.len());
    for a in &a.objects {
        let b = b.objects.iter().find(|b| b.head == a.head).unwrap();
        assert_eq!(a.wire, b.wire);
    }
}
#[test]
fn full_history_round_trip_is_authenticated_atomic_and_offline() {
    tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
        let directory=tempfile::tempdir().unwrap();
        let mut source=SqliteStore::open(&directory.path().join("source.sqlite")).unwrap();
        let target_path=directory.path().join("target.sqlite");
        let mut target=SqliteStore::open(&target_path).unwrap();
        let mut engine=Engine::default(); let mut keys=Keys::default();
        let Output::Created(created)=run(&mut engine,&mut source,&mut keys,Command::Create {name:"Fixture".into(),password:PASSWORD.into(),remember:true}).await.unwrap() else {panic!("created")};
        let id=created.info.id;
        let mut draft=app::new_record().unwrap(); draft.title=PRIVATE.into(); draft.tags=vec!["private-tag-fixture".into()];
        let mut field=app::field("password/v1").unwrap(); field.values.insert("password".into(),PRIVATE.into()); draft.fields.push(field);
        run(&mut engine,&mut source,&mut keys,Command::Save {draft:draft.clone(),epoch:1}).await.unwrap();
        let Output::Draft(mut draft)=run(&mut engine,&mut source,&mut keys,Command::Open {record:draft.record}).await.unwrap() else {panic!("draft")};
        draft.title="Second revision".into();
        run(&mut engine,&mut source,&mut keys,Command::Save {draft:draft.clone(),epoch:2}).await.unwrap();
        let deleted=app::new_record().unwrap();
        run(&mut engine,&mut source,&mut keys,Command::Save {draft:deleted.clone(),epoch:3}).await.unwrap();
        let head=source.head(id,deleted.record).await.unwrap().unwrap();
        run(&mut engine,&mut source,&mut keys,Command::Delete {record:deleted.record,expected:head.revision,epoch:4}).await.unwrap();
        #[cfg(not(feature = "export-check"))]
        {
            use app::{export, export_flow as flow};
            let before = source.snapshot(id).await.unwrap();
            let Output::VendorExport(Ok(flow::Reply::Reviewed { review, .. })) = run(
                &mut engine, &mut source, &mut keys,
                Command::VendorExport(flow::Command::Prepare {
                    operation: 1,
                    created_at: 1_735_689_600,
                    format: export::Format::BitwardenJson,
                    options: export::Options::Plain,
                    selection: flow::Selection::All,
                }),
            ).await.unwrap() else { panic!("vendor review"); };
            assert_eq!((review.records, review.blocked), (1, 0));
            let Output::VendorExport(Ok(flow::Reply::Ready { ready, .. })) = run(
                &mut engine, &mut source, &mut keys,
                Command::VendorExport(flow::Command::Generate {
                    operation: 2, token: review.token, consent: export::Consent::AllowLosses,
                }),
            ).await.unwrap() else { panic!("vendor artifact"); };
            let clear = engine.export_chunk(ready.token, 0).unwrap();
            assert!(clear.next.is_none());
            assert!(clear.bytes.windows(PRIVATE.len()).any(|bytes| bytes == PRIVATE.as_bytes()));
            assert!(matches!(run(
                &mut engine, &mut source, &mut keys,
                Command::VendorExport(flow::Command::Finish { token: ready.token }),
            ).await.unwrap(), Output::VendorExport(Ok(flow::Reply::Finished))));
            same(&before, &source.snapshot(id).await.unwrap());
        }
        let Output::Backup(bytes)=run(&mut engine,&mut source,&mut keys,Command::ExportBackup).await.unwrap() else {panic!("backup")};
        assert!(!bytes.windows(PRIVATE.len()).any(|v|v==PRIVATE.as_bytes()));
        assert!(!bytes.windows(created.key.len()).any(|v|v==created.key.as_bytes()));
        assert!(!bytes.windows(PASSWORD.len()).any(|v|v==PASSWORD.as_bytes()));
        assert!(!bytes.windows(19).any(|v|v==b"private-tag-fixture"));
        assert_eq!(app::backup::inspect(&bytes).unwrap(),id);
        let mut zip=ZipArchive::new(Cursor::new(&bytes)).unwrap();
        for i in 0..zip.len() {
            let mut file=zip.by_index(i).unwrap(); let name=file.name().unwrap().into_owned();
            if name.starts_with("backup.") {continue;}
            let mut wire=Vec::new(); file.read_to_end(&mut wire).unwrap();
            let digest=confidexsyncd::digest(&wire);
            if name.ends_with(".sealed") { assert!(name.ends_with(&format!("/locks/{digest}.sealed"))); }
            else {assert!(name.ends_with(&format!("/{}/{}/{}",&digest[..2],&digest[2..4],&digest[4..])));}
        }
        assert!(matches!(app::backup::restore(&bytes,"Restored","wrong",&created.key),Err(Error::Auth)));
        assert!(matches!(app::backup::restore(&bytes,"Restored",PASSWORD,"bad-key"),Err(Error::Key)));
        let damaged=rewrite(&bytes,|name,data| {if !name.starts_with("backup.") && !name.ends_with(".sealed") {data[0]^=1;} true});
        assert!(app::backup::inspect(&damaged).is_ok());
        assert!(matches!(app::backup::restore(&damaged,"Restored","wrong",&created.key),Err(Error::Auth)));
        assert!(matches!(app::backup::restore(&damaged,"Restored",PASSWORD,&created.key),Err(Error::Integrity)));
        let changed=rewrite(&bytes,|name,data| {if name=="backup.json" {data.push(b' ');} true});
        assert!(matches!(app::backup::restore(&changed,"Restored",PASSWORD,&created.key),Err(Error::Integrity)));
        let missing=rewrite(&bytes,|name,_| name=="backup.json" || name=="backup.sig" || name.ends_with(".sealed"));
        assert!(matches!(app::backup::restore(&missing,"Restored",PASSWORD,&created.key),Err(Error::Integrity)));
        assert!(target.vaults().await.unwrap().is_empty());
        let (snapshot,_)=app::backup::restore(&bytes,"Restored",PASSWORD,&created.key).unwrap();
        assert_eq!(snapshot.objects.len(),4);
        let connection=rusqlite::Connection::open(&target_path).unwrap();
        connection.execute_batch("CREATE TRIGGER fail_restore BEFORE INSERT ON objects BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
        assert!(target.restore(&snapshot).await.is_err()); assert!(target.vaults().await.unwrap().is_empty());
        connection.execute_batch("DROP TRIGGER fail_restore").unwrap();
        let mut imported=Engine::default(); let mut imported_keys=Keys::default();
        run(&mut imported,&mut target,&mut imported_keys,Command::InspectBackup{archive:bytes.clone()}).await.unwrap();
        assert!(matches!(run(&mut imported,&mut target,&mut imported_keys,Command::RestoreBackup{name:"Restored".into(),password:"wrong".into(),key:created.key.clone(),remember:true}).await,Err(Error::Auth)));
        run(&mut imported,&mut target,&mut imported_keys,Command::RestoreBackup{name:"Restored".into(),password:PASSWORD.into(),key:created.key.clone(),remember:true}).await.unwrap();
        assert_eq!(imported_keys.0.get(&id),Some(&created.key));
        same(&source.snapshot(id).await.unwrap(),&target.snapshot(id).await.unwrap());
        assert_eq!(target.tagged_heads(id,"private-tag-fixture",None).await.unwrap().len(),1);
        let Output::Rows{rows,..}=run(&mut imported,&mut target,&mut imported_keys,Command::List{after:None,tag:None}).await.unwrap() else {panic!("rows")};
        assert_eq!(rows.len(),1); assert_eq!(rows[0].title,"Second revision");
        assert!(matches!(target.restore(&snapshot).await,Err(confidex_storage::Error::Conflict)));
        same(&snapshot,&target.snapshot(id).await.unwrap());
        run(&mut imported,&mut target,&mut imported_keys,Command::Lock).await.unwrap();
        run(&mut imported,&mut target,&mut imported_keys,Command::Unlock{vault:id,password:PASSWORD.into(),key:created.key.clone(),remember:false}).await.unwrap();
        run(&mut imported,&mut target,&mut imported_keys,Command::InspectBackup{archive:bytes}).await.unwrap();
        run(&mut imported,&mut target,&mut imported_keys,Command::Lock).await.unwrap();
        assert!(matches!(run(&mut imported,&mut target,&mut imported_keys,Command::RestoreBackup{name:"Restored".into(),password:PASSWORD.into(),key:created.key.clone(),remember:false}).await,Err(Error::Input)));
    });
}

#[test]
fn empty_vault_and_downloaded_records_without_local_heads_are_preserved() {
    use confidex_storage::{Head, StoredObject, StoredVault, SyncCommit, VaultInfo};
    use confidex_vault::{envelope, kdf, lock, record::Record, resources::MAX_OPEN_MEMORY};
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let mut store = SqliteStore::open(&dir.path().join("staged.sqlite")).unwrap();
            let created = lock::create(PASSWORD.as_bytes(), kdf::REQUIRED_MEMORY).unwrap();
            let vault = &created.vault;
            let key = String::from_utf8(
                confidex_vault::transfer_code::encode(
                    &vault.keys().secret_key(),
                    vault.keys().signing_key().verifying_key().as_bytes(),
                )
                .to_vec(),
            )
            .unwrap();
            store
                .create(&StoredVault {
                    info: VaultInfo {
                        id: vault.vault_id(),
                        name: "Empty".into(),
                    },
                    lock: created.lock,
                })
                .await
                .unwrap();
            let empty = app::backup::export(&mut store, vault).await.unwrap();
            assert!(
                app::backup::restore(&empty, "Empty", PASSWORD, &key)
                    .unwrap()
                    .0
                    .objects
                    .is_empty()
            );
            let wire = envelope::seal(
                &Record::default(),
                vault.keys(),
                envelope::Options {
                    vault_id: vault.vault_id(),
                    record_id: [7; 16],
                    parents: &[],
                    epoch: 1,
                    kind: envelope::EventKind::Content,
                },
                MAX_OPEN_MEMORY,
            )
            .unwrap();
            let revision = envelope::verify(&wire, vault.anchor(), None, MAX_OPEN_MEMORY)
                .unwrap()
                .id();
            store
                .sync_commit(
                    vault.vault_id(),
                    &SyncCommit {
                        previous: None,
                        current: b"{}".to_vec(),
                        objects: vec![StoredObject {
                            head: Head {
                                record: [7; 16],
                                revision,
                            },
                            wire,
                            tags: vec![],
                        }],
                        heads: vec![],
                    },
                )
                .await
                .unwrap();
            let bytes = app::backup::export(&mut store, vault).await.unwrap();
            let (restored, _) = app::backup::restore(&bytes, "Restored", PASSWORD, &key).unwrap();
            assert_eq!(restored.objects.len(), 1);
            assert_eq!(restored.heads.len(), 1);
            assert_eq!(restored.heads[0].revision, revision);
        });
}

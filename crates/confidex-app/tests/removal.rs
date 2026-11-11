#![cfg(not(target_arch = "wasm32"))]
use confidex_app::{self as app, Command, DeviceKeys, Engine, Error, Output, Request};
use confidex_storage::{SqliteStore, Store};
use std::collections::BTreeMap;
use zeroize::Zeroize;

#[derive(Default)]
struct Keys {
    values: BTreeMap<[u8; 16], String>,
    fail_removal: bool,
}
impl DeviceKeys for Keys {
    async fn load(&mut self, vault: [u8; 16]) -> Option<String> {
        self.values.get(&vault).cloned()
    }
    async fn save(&mut self, vault: [u8; 16], key: &str) -> bool {
        self.values.insert(vault, key.into());
        true
    }
    async fn remove(&mut self, vault: [u8; 16]) -> bool {
        if self.fail_removal {
            return false;
        }
        if let Some(mut key) = self.values.remove(&vault) {
            key.zeroize();
        }
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
#[test]
fn closed_and_current_vaults_are_removed_without_replacing_another_session() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vaults.sqlite");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut store=SqliteStore::open(&path).unwrap();
        let mut keys=Keys::default();
        let mut current=Engine::default();
        let mut other=Engine::default();
        let Output::Created(a)=run(&mut current,&mut store,&mut keys,Command::Create {name:"Current".into(),password:"public-removal-fixture".into(),remember:true}).await.unwrap() else {panic!()};
        let Output::Created(b)=run(&mut other,&mut store,&mut keys,Command::Create {name:"Other".into(),password:"public-other-fixture".into(),remember:true}).await.unwrap() else {panic!()};
        let lock_before = store.vault(b.info.id).await.unwrap().lock;
        let renamed = run(&mut current,&mut store,&mut keys,Command::RenameVault {vault:b.info.id,expected:"Other".into(),name:"  Renamed local vault  ".into()}).await.unwrap();
        assert!(matches!(renamed,Output::Renamed(info) if info.id==b.info.id && info.name=="Renamed local vault"));
        assert_eq!(store.vault(b.info.id).await.unwrap().lock,lock_before);
        assert_eq!(keys.values.get(&b.info.id),Some(&b.key));
        assert!(matches!(run(&mut current,&mut store,&mut keys,Command::RenameVault {vault:b.info.id,expected:"Other".into(),name:"Stale".into()}).await,Ok(Output::RenameConflict(info)) if info.name=="Renamed local vault"));
        for name in [" ".to_owned(),"雪".repeat(43)] {
            assert!(matches!(run(&mut current,&mut store,&mut keys,Command::RenameVault {vault:b.info.id,expected:"Renamed local vault".into(),name}).await,Err(Error::Input)));
        }
        let mut draft=app::new_record().unwrap();draft.title="Public fixture".into();draft.tags=vec!["local-index".into()];
        run(&mut other,&mut store,&mut keys,Command::Save {draft:draft.clone(),epoch:1}).await.unwrap();
        let prepare=|password:&str|Command::PrepareRemoval {vault:b.info.id,password:password.into(),key:String::new(),synchronize:false};
        assert!(matches!(run(&mut current,&mut store,&mut keys,prepare("wrong")).await,Err(Error::Auth)));
        let Output::Created(still_current)=run(&mut current,&mut store,&mut keys,Command::ExportKey).await.unwrap() else {panic!()};
        assert_eq!(still_current.info.id,a.info.id);
        let Output::RemovalPrepared {created,report}=run(&mut current,&mut store,&mut keys,prepare("public-other-fixture")).await.unwrap() else {panic!()};
        assert_eq!(created.key,b.key);assert!(report.is_none());
        let Output::RemovalPrepared {created,..}=run(&mut current,&mut store,&mut keys,Command::PrepareRemoval {vault:a.info.id,password:String::new(),key:String::new(),synchronize:false}).await.unwrap() else {panic!()};
        assert_eq!(created.key,a.key);
        let db=rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("CREATE TRIGGER refuse_records BEFORE DELETE ON objects BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
        assert!(matches!(run(&mut current,&mut store,&mut keys,Command::RemoveVault {vault:b.info.id}).await,Err(Error::Storage(_))));
        assert_eq!(store.snapshot(b.info.id).await.unwrap().objects.len(),1);
        assert_eq!(keys.values.get(&b.info.id),Some(&b.key));
        db.execute_batch("DROP TRIGGER refuse_records").unwrap();
        keys.fail_removal=true;
        assert!(matches!(run(&mut current,&mut store,&mut keys,Command::RemoveVault {vault:b.info.id}).await,Ok(Output::Removed { result:Err(Error::Credentials), .. })));
        assert_eq!(store.vaults().await.unwrap().len(),2);
        keys.fail_removal=false;
        db.execute_batch("CREATE TRIGGER refuse_removal BEFORE DELETE ON vaults BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
        assert!(matches!(run(&mut current,&mut store,&mut keys,Command::RemoveVault {vault:b.info.id}).await,Ok(Output::Removed { result:Err(Error::Storage(_)), .. })));
        assert!(!keys.values.contains_key(&b.info.id));
        assert!(matches!(store.snapshot(b.info.id).await,Err(confidex_storage::Error::Removing)));
        let mut restarted=SqliteStore::open(&path).unwrap();
        assert!(matches!(restarted.vault(b.info.id).await,Err(confidex_storage::Error::Removing)));
        assert!(restarted.heads(b.info.id,None).await.unwrap().is_empty());
        db.execute_batch("DROP TRIGGER refuse_removal").unwrap();
        assert!(matches!(run(&mut current,&mut store,&mut keys,Command::RemoveVault {vault:b.info.id}).await.unwrap(),Output::Removed {vault:id,result:Ok(())} if id==b.info.id));
        assert!(!keys.values.contains_key(&b.info.id));
        assert!(matches!(run(&mut other,&mut store,&mut keys,Command::Save {draft,epoch:2}).await,Err(Error::Storage(confidex_storage::Error::NotFound))));
        let Output::Created(still_current)=run(&mut current,&mut store,&mut keys,Command::ExportKey).await.unwrap() else {panic!()};
        assert_eq!(still_current.key,a.key);
        run(&mut current,&mut store,&mut keys,Command::RemoveVault {vault:a.info.id}).await.unwrap();
        assert!(keys.values.is_empty());assert!(store.vaults().await.unwrap().is_empty());
        assert!(matches!(run(&mut current,&mut store,&mut keys,Command::List {after:None,tag:None}).await,Err(Error::Locked)));
        run(&mut current,&mut store,&mut keys,Command::RemoveVault {vault:a.info.id}).await.unwrap();
    });
}

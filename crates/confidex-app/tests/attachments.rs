#![cfg(not(target_arch = "wasm32"))]
use confidex_app::{self as app, Command, DeviceKeys, Engine, Error, Output, Request};
use confidex_storage::{SqliteStore, Store};

struct Keys;
impl DeviceKeys for Keys {
    async fn remove(&mut self, _: [u8; 16]) -> bool {
        true
    }
    async fn load(&mut self, _: [u8; 16]) -> Option<String> {
        None
    }
    async fn save(&mut self, _: [u8; 16], _: &str) -> bool {
        false
    }
}
async fn run(
    engine: &mut Engine,
    store: &mut SqliteStore,
    command: Command,
) -> Result<Output, Error> {
    engine
        .execute(
            store,
            &mut Keys,
            &mut Request {
                generation: 0,
                command,
            },
        )
        .await
        .result
}
fn noise(seed: u64, count: usize) -> Vec<u8> {
    let mut x = seed;
    (0..count)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}
#[test]
fn encrypted_attachments_reopen_and_the_complete_record_limit_is_atomic() {
    tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SqliteStore::open(&dir.path().join("attachments.sqlite")).unwrap();
        let mut engine = Engine::default();
        let Output::Created(created) = run(&mut engine, &mut store, Command::Create {
            name: "Public attachment test".into(), password: "Public-attachment-password".into(), remember: false,
        }).await.unwrap() else { panic!("created"); };
        let mut draft = app::new_record().unwrap();
        draft.title = "Software license".into();
        let mut file = app::field("file/v1").unwrap();
        file.name = "License file".into();
        file.values.insert("filename".into(), "product.license".into());
        let expected = noise(42, 2_100_000);
        file.data = Some(expected.clone().into());
        draft.fields.push(file);
        let ssh_source = include_bytes!("../../confidex-ui/tests/fixtures/public-ssh-key.pem");
        let Output::Ssh { token, result: Ok(ssh) } = run(&mut engine, &mut store, Command::ImportSsh { token: 42, data: ssh_source.to_vec(), password: Some("public-fixture-passphrase".into()) }).await.unwrap() else { panic!("ssh import"); };
        assert_eq!(token, 42);
        let fingerprint = ssh.values["fingerprint"].clone();
        draft.fields.push(ssh);
        draft.sections = Some(vec![app::sections::Section::new("Attachments", 0, 1), app::sections::Section::new("Empty", 1, 0)]);
        assert!(matches!(run(&mut engine, &mut store, Command::CheckDraft { draft: draft.clone() }).await.unwrap(), Output::Checked { compressed } if compressed < 4_000_000));
        assert!(store.heads(created.info.id, None).await.unwrap().is_empty());
        let record = draft.record;
        run(&mut engine, &mut store, Command::Save { draft, epoch: 1 }).await.unwrap();
        let head = store.head(created.info.id, record).await.unwrap().unwrap();
        run(&mut engine, &mut store, Command::Lock).await.unwrap();
        run(&mut engine, &mut store, Command::Unlock { vault: created.info.id, password: "Public-attachment-password".into(), key: created.key.clone(), remember: false }).await.unwrap();
        let Output::Draft(mut draft) = run(&mut engine, &mut store, Command::Open { record }).await.unwrap() else { panic!("draft"); };
        assert_eq!(&**draft.fields[0].data.as_ref().unwrap(), expected.as_slice());
        assert_eq!(draft.fields[0].values["filename"], "product.license");
        assert_eq!(draft.fields[1].values["fingerprint"], fingerprint);
        assert!(draft.fields[1].protected);
        assert_eq!(draft.fields[1].values["key_type"], "Ed25519");
        let sections = draft.sections.as_ref().unwrap();
        assert_eq!((sections[0].name.as_str(), sections[0].start, sections[0].count), ("Attachments", 0, 1));
        assert_eq!((sections[1].name.as_str(), sections[1].count), ("Empty", 0));
        let mut second = app::field("file/v1").unwrap();
        second.data = Some(noise(99, 2_100_000).into());
        draft.fields.push(second);
        assert!(matches!(run(&mut engine, &mut store, Command::CheckDraft { draft: draft.clone() }).await, Err(Error::RecordLimit)));
        assert!(matches!(run(&mut engine, &mut store, Command::Save { draft, epoch: 2 }).await, Err(Error::RecordLimit)));
        assert_eq!(store.head(created.info.id, record).await.unwrap().unwrap().revision, head.revision);
        let Output::Draft(draft) = run(&mut engine, &mut store, Command::Open { record }).await.unwrap() else { panic!("unchanged"); };
        assert_eq!(draft.fields.len(), 2);
        assert_eq!(draft.fields[1].values["fingerprint"], fingerprint);
        assert_eq!(&**draft.fields[0].data.as_ref().unwrap(), expected.as_slice());
    });
}

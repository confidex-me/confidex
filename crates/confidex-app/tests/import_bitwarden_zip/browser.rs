// This test probe uses the application's real BrowserStore without UI wiring.
use crate::browser_store::{BrowserKeys, BrowserStore};
use confidex_app::{
    Command, Engine, Output, Request,
    import::{self, Format, Limits, Status},
    import_apply::{Action, Choice, Error, Match, Selection},
};
use confidex_storage::Store;
use confidex_vault::{envelope, kdf, lock, resources::MAX_OPEN_MEMORY, transfer_code};
use wasm_bindgen::prelude::*;
const ZIP: &[u8] = include_bytes!("../import_fixtures/bitwarden_zip/personal.zip");
const PASSWORD: &str = "public-browser-zip-probe-password";
fn plan(bytes: &[u8]) -> import::Plan {
    let mut options = import::Options::default();
    options.source_instance = Some("public-zip-source".into());
    import::prepare(
        Format::BitwardenZip,
        bytes,
        &options,
        Limits::default(),
        &mut |_| true,
        import::formats::bitwarden_zip::parse,
    )
    .unwrap()
}
async fn command(engine: &mut Engine, command: Command) -> Output {
    engine
        .execute(
            &mut BrowserStore,
            &mut BrowserKeys,
            &mut Request {
                generation: 1,
                command,
            },
        )
        .await
        .result
        .unwrap()
}
#[wasm_bindgen]
pub async fn check_zip() -> String {
    let mut engine = Engine::default();
    let Output::Created(created) = command(
        &mut engine,
        Command::Create {
            name: "Public ZIP probe".into(),
            password: PASSWORD.into(),
            remember: false,
        },
    )
    .await
    else {
        panic!("Create output")
    };
    let id = created.info.id;
    let expected = plan(ZIP);
    let review = engine
        .review_import(&mut BrowserStore, id, plan(ZIP), &mut |_| true)
        .await
        .unwrap();
    assert_eq!(review.container_status, Status::Review);
    assert!(BrowserStore.heads(id, None).await.unwrap().is_empty());
    for (a, b) in engine
        .import_plan(review.token)
        .unwrap()
        .items
        .iter()
        .zip(&expected.items)
    {
        assert_eq!(a.record_bytes(), b.record_bytes());
    }
    let choices = Selection {
        container_reviewed: true,
        choices: (0..3)
            .map(|_| Choice {
                action: Action::Create,
                reviewed: true,
            })
            .collect(),
    };
    let report = engine
        .apply_import(&mut BrowserStore, review.token, &choices, 10, &mut |_| true)
        .await
        .unwrap();
    assert_eq!(report.added, 3);
    let stored = BrowserStore.vault(id).await.unwrap();
    let code = transfer_code::decode(&created.key).unwrap();
    let vault = lock::open(
        &stored.lock,
        PASSWORD.as_bytes(),
        &code.secret,
        kdf::REQUIRED_MEMORY,
    )
    .unwrap();
    let mut actual = Vec::new();
    for head in BrowserStore.heads(id, None).await.unwrap() {
        let wire = BrowserStore.object(id, head.revision).await.unwrap();
        assert!(!wire.windows(23).any(|w| w == b"PUBLIC-FIXTURE-PASSWORD"));
        let mut record = envelope::open(
            &wire,
            vault.keys(),
            vault.anchor(),
            Some(&head.revision),
            MAX_OPEN_MEMORY,
        )
        .unwrap()
        .record;
        assert!(record.extra.remove("confidex.import.origin").is_some());
        actual.push(
            record
                .encode_content(MAX_OPEN_MEMORY)
                .unwrap()
                .bytes
                .to_vec(),
        );
    }
    let mut expected: Vec<_> = expected
        .items
        .iter()
        .map(|i| i.record_bytes().to_vec())
        .collect();
    actual.sort();
    expected.sort();
    assert_eq!(actual, expected);
    command(&mut engine, Command::Lock).await;
    drop(engine);
    let mut engine = Engine::default();
    command(
        &mut engine,
        Command::Unlock {
            vault: id,
            password: PASSWORD.into(),
            key: created.key.clone(),
            remember: false,
        },
    )
    .await;
    engine.begin_import().unwrap();
    let review = engine
        .review_import(&mut BrowserStore, id, plan(ZIP), &mut |_| true)
        .await
        .unwrap();
    assert!(review.items.iter().all(|i| i.matching == Match::Duplicate));
    let skip = Selection {
        container_reviewed: true,
        choices: (0..3)
            .map(|_| Choice {
                action: Action::Skip,
                reviewed: true,
            })
            .collect(),
    };
    let result = engine
        .apply_import(&mut BrowserStore, review.token, &skip, 11, &mut |_| true)
        .await
        .unwrap();
    assert_eq!(result.skipped, 3);
    for zip in [
        include_bytes!("../import_fixtures/bitwarden_zip/duplicate.zip").as_slice(),
        include_bytes!("../import_fixtures/bitwarden_zip/restricted.zip").as_slice(),
    ] {
        engine.begin_import().unwrap();
        let review = engine
            .review_import(&mut BrowserStore, id, plan(zip), &mut |_| true)
            .await
            .unwrap();
        assert_eq!(review.container_status, Status::Blocked);
        let skip = Selection {
            container_reviewed: true,
            choices: review
                .items
                .iter()
                .map(|_| Choice {
                    action: Action::Skip,
                    reviewed: true,
                })
                .collect(),
        };
        assert_eq!(
            engine
                .apply_import(&mut BrowserStore, review.token, &skip, 12, &mut |_| true)
                .await,
            Err(Error::InvalidChoice)
        );
    }
    assert_eq!(BrowserStore.snapshot(id).await.unwrap().objects.len(), 3);
    command(&mut engine, Command::Lock).await;
    BrowserStore.remove(id).await.unwrap();
    "preview,3 sealed records,binary equality,reopen,duplicate skip,blocked collisions/orphans"
        .into()
}

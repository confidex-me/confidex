//! Synthetic real-Store checks, excluded from normal client builds.
use crate::browser_store::BrowserStore;
use wasm_bindgen::prelude::*;
#[path = "../../../crates/confidex-app/tests/export_bitwarden_json/proof.rs"]
mod bitwarden;
#[path = "../../../crates/confidex-app/tests/export_bitwarden_encrypted/proof.rs"]
mod bitwarden_encrypted;
#[path = "../../../crates/confidex-app/tests/export_bitwarden_zip/proof.rs"]
mod bitwarden_zip;
#[path = "../../../crates/confidex-app/tests/export_csv/proof.rs"]
mod csv;
#[path = "../../../crates/confidex-app/tests/export_kdbx/proof.rs"]
mod kdbx;
#[path = "../../../crates/confidex-app/tests/export_keepass_xml/proof.rs"]
mod keepass;
#[path = "../../../crates/confidex-app/tests/export_fixtures/keepass_common.rs"]
mod keepass_common;
#[path = "../../../crates/confidex-app/tests/export_onepassword_1pux/proof.rs"]
mod onepassword;
#[path = "../../../crates/confidex-app/tests/export_flow/proof.rs"]
mod proof;
#[wasm_bindgen]
pub async fn sample_export_reverse() -> Result<String, JsValue> {
    #[cfg(not(feature = "export-check"))]
    {
        Ok(serde_json::to_string(&proof::reverse_exports(&mut BrowserStore).await).unwrap())
    }
    #[cfg(feature = "export-check")]
    {
        Err("reverse export requires genuine writer factories".into())
    }
}

#[wasm_bindgen]
pub async fn check_export(mode: &str) -> Result<(), JsValue> {
    match mode {
        "locales" => confidex_ui::i18n::check_export_catalogues()
            .map_err(|error| JsValue::from_str(&error))?,
        "current" => proof::current_records(&mut BrowserStore).await,
        "field-sources" => proof::field_sources(&mut BrowserStore).await,
        "field-sources-service" => field_sources_service().await?,
        "bitwarden" => bitwarden::run(),
        "bitwarden-encrypted" => bitwarden_encrypted::run(),
        "bitwarden-encrypted-store" => proof::encrypted_records(&mut BrowserStore).await,
        "bitwarden-zip" => bitwarden_zip::run(),
        "csv" => csv::run(),
        "csv-setup" => confidex_ui::ui_kit::exporter::check_csv_setup(),
        "keepass" => keepass::run(),
        "kdbx" => kdbx::run(),
        #[cfg(not(feature = "export-check"))]
        "kdbx-registry" => proof::kdbx_registry(&mut BrowserStore).await,
        "onepassword" => onepassword::run(),
        #[cfg(not(feature = "export-check"))]
        "bitwarden-flow" => proof::bitwarden_profiles(&mut BrowserStore).await,
        #[cfg(not(feature = "export-check"))]
        "plain-formats" => proof::plain_formats(&mut BrowserStore).await,
        #[cfg(not(feature = "export-check"))]
        "csv-factory" => proof::csv_factory(&mut BrowserStore).await,
        "consent" => proof::consent_and_failures(&mut BrowserStore).await,
        "storage-failure" => {
            proof::storage_failure(&mut BrowserStore, |_, enabled| export_db_failure(enabled)).await
        }
        "invalidation" => proof::invalidation(&mut BrowserStore).await,
        "changed" => proof::changed_heads(&mut BrowserStore).await,
        "cancel" => proof::cancellation(&mut BrowserStore).await,
        "tombstones" => proof::tombstones(&mut BrowserStore).await,
        #[cfg(feature = "export-check")]
        "protocol" => proof::protocol(&mut BrowserStore).await,
        #[cfg(feature = "export-check")]
        "service" => service().await?,
        _ => return Err("unknown public export check".into()),
    }
    Ok(())
}

#[wasm_bindgen(inline_js = "
let transaction;
export function export_db_failure(enabled) {
    if (enabled) {
        if (transaction) throw Error('Overlapping database failure');
        transaction = IDBDatabase.prototype.transaction;
        IDBDatabase.prototype.transaction = function(...args) {
            if (args[1] === 'readonly') throw new DOMException('Injected read failure', 'InvalidStateError');
            return transaction.apply(this, args);
        };
    } else {
        if (!transaction) throw Error('Missing database failure');
        IDBDatabase.prototype.transaction = transaction;
        transaction = undefined;
    }
}")]
extern "C" {
    fn export_db_failure(enabled: bool);
}

#[wasm_bindgen]
pub async fn profile_export_load() -> Result<String, JsValue> {
    #[cfg(not(feature = "export-check"))]
    {
        let report = proof::load(&mut BrowserStore, export_load_now).await;
        Ok(serde_json::to_string(&report).unwrap())
    }
    #[cfg(feature = "export-check")]
    Err("export calibration requires genuine writer factories".into())
}

#[wasm_bindgen]
pub async fn profile_export_faults() -> Result<String, JsValue> {
    #[cfg(not(feature = "export-check"))]
    {
        let mut entropy = |enabled| export_entropy_failure(enabled);
        let report = proof::load_faults(
            &mut BrowserStore,
            |_, enabled| export_db_failure(enabled),
            Some(&mut entropy),
        )
        .await;
        Ok(serde_json::to_string(&report).unwrap())
    }
    #[cfg(feature = "export-check")]
    Err("export failure calibration requires genuine writer factories".into())
}

#[cfg(not(feature = "export-check"))]
#[wasm_bindgen(inline_js = "
let random;
export function export_entropy_failure(enabled) {
    if (enabled) {
        if (random) throw Error('Overlapping entropy failure');
        random = self.crypto.getRandomValues;
        self.crypto.getRandomValues = function() { throw Error('Injected entropy failure'); };
    } else {
        if (!random) throw Error('Missing entropy failure');
        self.crypto.getRandomValues = random;
        random = undefined;
    }
}")]
extern "C" {
    fn export_entropy_failure(enabled: bool);
}

#[wasm_bindgen]
pub async fn seed_export_load_ui_check() -> Result<String, JsValue> {
    #[cfg(not(feature = "export-check"))]
    {
        let (fixture, ..) = proof::seed_load(&mut BrowserStore, export_load_now).await;
        Ok(serde_json::to_string(&fixture.created).unwrap())
    }
    #[cfg(feature = "export-check")]
    Err("export calibration requires genuine writer factories".into())
}

#[cfg(not(feature = "export-check"))]
#[wasm_bindgen(inline_js = "export function export_load_now() { return performance.now(); }")]
extern "C" {
    fn export_load_now() -> f64;
}

#[wasm_bindgen]
pub fn sample_kdbx_export(mode: u8) -> Result<Vec<u8>, JsValue> {
    if mode > 4 {
        return Err("unknown public credential mode".into());
    }
    kdbx::artifact(usize::from(mode))
        .map(|file| file.bytes().to_vec())
        .map_err(|error| JsValue::from_str(&error.to_string()))
}

#[wasm_bindgen]
pub async fn seed_export_check() -> String {
    let fixture = proof::fixture(&mut BrowserStore).await;
    serde_json::to_string(&fixture.created).unwrap()
}

#[wasm_bindgen]
pub async fn seed_branches_ui_check() -> String {
    use confidex_storage::{Head, HeadChange, Store, StoredObject, SyncCommit};
    use confidex_vault::{
        envelope,
        record::{Entry, Mapping, Record},
        resources::MAX_OPEN_MEMORY,
    };
    let fixture = proof::fixture(&mut BrowserStore).await;
    confidex_app::sync::configure(&mut BrowserStore, &fixture.vault, None)
        .await
        .unwrap();
    let previous = BrowserStore
        .sync_state(fixture.vault.vault_id())
        .await
        .unwrap();
    let mut heads = Vec::new();
    let mut objects = Vec::new();
    let mut changes = Vec::new();
    for (index, tag) in ["branch-a", "branch-b"].into_iter().enumerate() {
        let mut record = Record::default();
        record.tags.push(tag.into());
        record
            .extra
            .insert("confidex.title".into(), "Public parallel account".into());
        record.entries.push(Entry {
            name: "Password".into(),
            type_name: "password/v1".into(),
            value: Mapping::from([("password".into(), "public-parallel-password".into())]),
            extra: Mapping::new(),
        });
        let wire = envelope::seal(
            &record,
            fixture.vault.keys(),
            envelope::Options {
                vault_id: fixture.vault.vault_id(),
                record_id: fixture.head.record,
                parents: &[fixture.head.revision],
                epoch: 10,
                kind: envelope::EventKind::Content,
            },
            MAX_OPEN_MEMORY,
        )
        .unwrap();
        let revision = envelope::verify(&wire, fixture.vault.anchor(), None, MAX_OPEN_MEMORY)
            .unwrap()
            .id();
        let head = Head {
            record: fixture.head.record,
            revision,
        };
        heads.push(head.clone());
        objects.push(StoredObject {
            head: head.clone(),
            wire,
            tags: record.tags.clone(),
        });
        changes.push(HeadChange {
            head,
            expected: (index == 0).then_some(fixture.head.revision),
        });
    }
    BrowserStore
        .publish_branches(
            fixture.vault.vault_id(),
            &SyncCommit {
                current: previous.clone().unwrap(),
                previous,
                objects,
                heads: changes,
            },
        )
        .await
        .unwrap();
    serde_json::json!({"created":fixture.created,"heads":heads}).to_string()
}

#[wasm_bindgen]
pub fn sample_bitwarden_encrypted_export(mode: u8) -> Result<Vec<u8>, JsValue> {
    use confidex_app::import::formats::bitwarden_json::Profile;
    let profile = match mode {
        0 => Profile::Personal,
        1 => Profile::Organization,
        _ => return Err("unknown public export profile".into()),
    };
    bitwarden_encrypted::artifact(profile).map_err(|error| JsValue::from_str(&format!("{error:?}")))
}

#[wasm_bindgen]
pub async fn seed_export_ui_check() -> String {
    let fixture = proof::fixture(&mut BrowserStore).await;
    let mut record = proof::content();
    record.extra.insert("export-ui-loss".into(), true.into());
    for index in 0..70 {
        record.entries.push(confidex_vault::record::Entry {
            name: format!("Public field {index}"),
            type_name: "password/v1".into(),
            value: confidex_vault::record::Mapping::from([(
                "password".into(),
                "public page fixture".into(),
            )]),
            extra: confidex_vault::record::Mapping::from([("protected".into(), true.into())]),
        });
    }
    proof::append(&mut BrowserStore, &fixture.vault, [2; 16], None, &record, 3).await;
    serde_json::to_string(&fixture.created).unwrap()
}

#[wasm_bindgen]
pub async fn seed_bitwarden_export_ui_check() -> String {
    use confidex_vault::record::{Entry, Mapping, Record};
    let fixture = proof::fixture(&mut BrowserStore).await;
    let mut record = Record::default();
    record.tags.push("demo".into());
    record
        .extra
        .insert("confidex.title".into(), "Public custom fields".into());
    for (name, kind, key, value) in [
        ("", "text/v1", "text", ""),
        ("Same", "text/v1", "text", "line one\n公開"),
        ("Same", "secret/v1", "secret", "PUBLIC-HIDDEN"),
    ] {
        record.entries.push(Entry {
            name: name.into(),
            type_name: kind.into(),
            value: Mapping::from([(key.into(), value.into())]),
            extra: Mapping::new(),
        });
    }
    proof::append(&mut BrowserStore, &fixture.vault, [2; 16], None, &record, 3).await;
    serde_json::to_string(&fixture.created).unwrap()
}

async fn service_call(
    service: &mut crate::browser::WorkerService,
    command: confidex_app::Command,
) -> Result<confidex_app::Output, JsValue> {
    use confidex_app::Request;
    use zeroize::Zeroizing;
    let bytes = crate::browser_wire::encode_request(Request {
        generation: 92,
        command,
    })
    .map_err(|_| JsValue::from_str("encode public request"))?;
    let output = service.execute(bytes).await?;
    let bytes = Zeroizing::new(output.to_vec());
    output.fill(0, 0, output.length());
    let response = crate::browser_wire::decode_response(&bytes)
        .map_err(|_| JsValue::from_str("decode public response"))?;
    assert_eq!(response.generation, 92);
    Ok(response.result.unwrap())
}

async fn field_sources_service() -> Result<(), JsValue> {
    use confidex_app::{Command, Output, export_flow as flow};
    let fixture = proof::fixture(&mut BrowserStore).await;
    let sample_head = proof::append(
        &mut BrowserStore,
        &fixture.vault,
        fixture.head.record,
        Some(fixture.head.revision),
        &proof::field_source_record(),
        3,
    )
    .await;
    let before = proof::snapshot(&mut BrowserStore, fixture.created.info.id).await;
    let mut service = crate::browser::WorkerService::new();
    assert!(matches!(
        service_call(
            &mut service,
            Command::Unlock {
                vault: fixture.created.info.id,
                password: "public-export-contract-password".into(),
                key: fixture.created.key.clone(),
                remember: false,
            }
        )
        .await?,
        Output::Opened { .. }
    ));
    let fields_command = || {
        Command::VendorExport(flow::Command::Fields {
            operation: 506,
            head: sample_head.clone(),
            start: 80,
        })
    };
    let Output::VendorExport(Ok(flow::Reply::Fields {
        operation: 506,
        vault,
        head,
        fields,
        start: 80,
    })) = service_call(&mut service, fields_command()).await?
    else {
        panic!("service field sources");
    };
    assert_eq!(vault, fixture.created.info.id);
    assert_eq!(head, sample_head);
    assert_eq!(fields.items.len(), flow::SOURCE_PAGE_SIZE);
    assert_eq!(fields.next, None);
    assert_eq!(fields.items[0].index, 78);
    assert_eq!(fields.items[0].type_name, "x".repeat(64));
    assert_eq!(fields.items[0].key, "\0".repeat(1024));
    let encoded = zeroize::Zeroizing::new(serde_json::to_string(&fields).unwrap());
    assert!(encoded.len() >= 450_000 && encoded.len() <= 1 << 20);
    assert!(!encoded.contains("PUBLIC-UNSENT") && !encoded.contains("公開.dat"));
    let mut setup = confidex_ui::ui_kit::exporter::CsvState::default();
    setup.begin_fields(506, sample_head.clone(), 80, 96);
    assert!(setup.accept(506, head.clone(), 80, fields).unwrap());
    assert_eq!(setup.sources().len(), flow::SOURCE_PAGE_SIZE);
    setup
        .add("Public column".into(), confidex_app::export::Source::Title)
        .unwrap();
    assert!(setup.valid());
    assert!(matches!(
        service_call(&mut service, Command::Lock).await?,
        Output::Locked
    ));
    setup = confidex_ui::ui_kit::exporter::CsvState::default();
    assert!(
        !setup
            .accept(506, head, 80, serde_json::from_str(&encoded).unwrap())
            .unwrap()
    );
    assert!(setup.sources().is_empty() && setup.manual.columns.is_empty());
    assert!(matches!(
        service_call(&mut service, fields_command()).await?,
        Output::VendorExport(Err(flow::Error::App(confidex_app::Error::Locked)))
    ));
    assert_eq!(
        *proof::snapshot(&mut BrowserStore, fixture.created.info.id).await,
        *before
    );
    Ok(())
}

#[cfg(feature = "export-check")]
async fn service() -> Result<(), JsValue> {
    use crate::browser::WorkerService;
    use confidex_app::{Command, Output, Request, export, export_flow as flow};
    use zeroize::Zeroizing;
    let fixture = proof::fixture(&mut BrowserStore).await;
    let before = proof::snapshot(&mut BrowserStore, fixture.created.info.id).await;
    let mut service = WorkerService::new();
    assert!(matches!(
        service_call(
            &mut service,
            Command::Unlock {
                vault: fixture.created.info.id,
                password: "public-export-contract-password".into(),
                key: fixture.created.key.clone(),
                remember: false
            }
        )
        .await?,
        Output::Opened { .. }
    ));
    assert!(matches!(
        service_call(&mut service, Command::VendorExport(flow::Command::Begin)).await?,
        Output::VendorExport(Ok(flow::Reply::Begun { .. }))
    ));
    let prepare = |operation| {
        Command::VendorExport(flow::Command::Prepare {
            operation,
            created_at: 1_735_689_600,
            format: export::Format::Kdbx,
            options: export::Options::Password {
                password: Some("".into()),
                keyfile: Some(vec![197; 4096]),
            },
            selection: flow::Selection::All,
        })
    };
    let Output::VendorExport(Ok(flow::Reply::Reviewed { review, .. })) =
        service_call(&mut service, prepare(60)).await?
    else {
        panic!("review");
    };
    let mut truncated = crate::browser_wire::encode_request(Request {
        generation: 92,
        command: prepare(61),
    })
    .unwrap();
    truncated.pop();
    assert!(service.execute(truncated).await.is_err());
    assert!(matches!(
        service_call(
            &mut service,
            Command::VendorExport(flow::Command::Rows {
                token: review.token,
                start: 0
            })
        )
        .await?,
        Output::VendorExport(Err(flow::Error::InvalidSession))
    ));
    let Output::VendorExport(Ok(flow::Reply::Reviewed { review, .. })) =
        service_call(&mut service, prepare(62)).await?
    else {
        panic!("retry");
    };
    set_canceled(63, 0);
    assert!(matches!(
        service_call(
            &mut service,
            Command::VendorExport(flow::Command::Generate {
                operation: 63,
                token: review.token,
                consent: export::Consent::Lossless
            })
        )
        .await?,
        Output::VendorExport(Err(flow::Error::Export(export::Error::Canceled)))
    ));
    let Output::VendorExport(Ok(flow::Reply::Reviewed { review, .. })) =
        service_call(&mut service, prepare(64)).await?
    else {
        panic!("retry after cancel");
    };
    set_canceled(0, 65);
    let Output::VendorExport(Ok(flow::Reply::Ready { ready, .. })) = service_call(
        &mut service,
        Command::VendorExport(flow::Command::Generate {
            operation: 65,
            token: review.token,
            consent: export::Consent::Lossless,
        }),
    )
    .await?
    else {
        panic!("ready");
    };
    let mut bytes = Zeroizing::new(Vec::new());
    let mut offset = 0;
    loop {
        let Output::VendorExport(Ok(flow::Reply::Chunk { chunk, .. })) = service_call(
            &mut service,
            Command::VendorExport(flow::Command::Chunk {
                token: ready.token,
                offset,
            }),
        )
        .await?
        else {
            panic!("chunk");
        };
        bytes.extend_from_slice(&chunk.bytes);
        if let Some(next) = chunk.next {
            offset = next;
        } else {
            break;
        }
    }
    assert_eq!(bytes.len(), ready.bytes);
    let record = confidex_vault::record::Record::decode_content(
        &bytes[4..],
        confidex_vault::resources::MAX_OPEN_MEMORY,
    )
    .unwrap()
    .record;
    assert_eq!(
        record.entries[0].value["password"].as_str(),
        Some("current public password\n第二行")
    );
    assert!(matches!(
        service_call(&mut service, Command::Lock).await?,
        Output::Locked
    ));
    assert!(matches!(
        service_call(
            &mut service,
            Command::VendorExport(flow::Command::Chunk {
                token: ready.token,
                offset: 0
            })
        )
        .await?,
        Output::VendorExport(Err(flow::Error::InvalidSession))
    ));
    assert_eq!(
        *proof::snapshot(&mut BrowserStore, fixture.created.info.id).await,
        *before
    );
    set_canceled(0, 0);
    Ok(())
}

#[wasm_bindgen]
pub async fn seed_kdbx_export_ui_check() -> String {
    use confidex_vault::record::{Entry, Mapping, Record};
    let fixture = proof::fixture(&mut BrowserStore).await;
    let mut record = Record::default();
    record
        .extra
        .insert("confidex.title".into(), "Public conflicting fields".into());
    for text in ["PUBLIC-FIRST", "PUBLIC-SECOND"] {
        record.entries.push(Entry {
            name: "Same".into(),
            type_name: "text/v1".into(),
            value: Mapping::from([("text".into(), text.into())]),
            extra: Mapping::new(),
        });
    }
    proof::append(&mut BrowserStore, &fixture.vault, [2; 16], None, &record, 3).await;
    serde_json::to_string(&fixture.created).unwrap()
}

#[wasm_bindgen(
    inline_js = "export function exportCheckCanceled(exportOp, importOp) { self.confidexExportCanceled=exportOp; self.confidexImportCanceled=importOp; }"
)]
extern "C" {
    #[wasm_bindgen(js_name=exportCheckCanceled)]
    fn set_canceled(export_op: u32, import_op: u32);
}

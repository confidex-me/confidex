//! Synthetic browser checks, excluded from normal client builds.
use crate::browser_store::{BrowserKeys, BrowserStore};
use confidex_app::{
    Command, Engine, Error as AppError, Output, Request,
    import::{self, Format, Limits, Plan},
    import_apply::{Action, Choice, Control, Error, Match, Phase, Progress, Review, Selection},
};
use confidex_storage::{Store, VaultId};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

const PASSWORD: &str = "public-wasm-import-check-password";
#[wasm_bindgen(
    inline_js = "export async function importCheckTick(phase,current,total){ self.postMessage({phase,current,total}); await new Promise(resolve=>setTimeout(resolve,0)); return !self.importCheckCanceled; }"
)]
extern "C" {
    #[wasm_bindgen(js_name = importCheckTick)]
    async fn import_check_tick(phase: u32, current: u32, total: u32) -> JsValue;
}
struct Yield;
impl Control for Yield {
    async fn checkpoint(&mut self, progress: Progress) -> bool {
        let phase = match progress.phase {
            Phase::Catalog => 0,
            Phase::Review => 1,
            Phase::Seal => 2,
            Phase::Commit => 3,
        };
        import_check_tick(phase, progress.current as u32, progress.total as u32)
            .await
            .as_bool()
            == Some(true)
    }
}
fn require(ok: bool, message: &str) -> Result<(), JsValue> {
    if ok { Ok(()) } else { Err(message.into()) }
}
async fn command(engine: &mut Engine, command: Command) -> Result<Output, JsValue> {
    engine
        .execute(
            &mut BrowserStore,
            &mut BrowserKeys::default(),
            &mut Request {
                generation: 1,
                command,
            },
        )
        .await
        .result
        .map_err(|error| format!("{error:?}").into())
}
fn plan(count: usize, prefix: &str) -> Result<Plan, JsValue> {
    let mut options = import::Options::default();
    options.source_instance = Some("public-browser-source".into());
    let items: Vec<_> = (0..count)
        .map(|index| {
            serde_json::json!({
                "id":format!("{prefix}-{index}"),"type":1,"name":format!("{prefix} {index}"),
                "notes":"private-wasm-note-needle",
                "fields":[{"name":"Public text","type":0,"value":"visible-wasm-needle"}],
                "login":{"password":"private-wasm-secret-needle","uris":[]}
            })
        })
        .collect();
    let input = Zeroizing::new(
        serde_json::to_vec(&serde_json::json!({"encrypted":false,"folders":[],"items":items}))
            .map_err(|_| JsValue::from_str("fixture encoding"))?,
    );
    import::prepare(
        Format::BitwardenJson,
        &input,
        &options,
        Limits::default(),
        &mut |_| true,
        import::formats::bitwarden_json::parse,
    )
    .map_err(|_| JsValue::from_str("fixture parser"))
}
async fn prepare_review(
    engine: &mut Engine,
    id: VaultId,
    count: usize,
    prefix: &str,
) -> Result<Review, JsValue> {
    require(
        engine
            .begin_import()
            .map_err(|_| JsValue::from_str("begin import"))?
            == id,
        "target vault changed",
    )?;
    engine
        .review_import(&mut BrowserStore, id, plan(count, prefix)?, &mut Yield)
        .await
        .map_err(|_| JsValue::from_str("review"))
}
fn choices(count: usize, action: Action) -> Selection {
    Selection {
        container_reviewed: true,
        choices: (0..count)
            .map(|_| Choice {
                action: action.clone(),
                reviewed: true,
            })
            .collect(),
    }
}
async fn size(id: VaultId) -> Result<(usize, usize), JsValue> {
    let snapshot = BrowserStore
        .snapshot(id)
        .await
        .map_err(|_| JsValue::from_str("snapshot"))?;
    Ok((snapshot.heads.len(), snapshot.objects.len()))
}
async fn search(engine: &mut Engine, text: &str) -> Result<usize, JsValue> {
    loop {
        match command(
            engine,
            Command::Search {
                query: text.into(),
                after: None,
                tag: None,
                refresh: false,
            },
        )
        .await?
        {
            Output::Indexing => (),
            Output::Rows { rows, .. } => return Ok(rows.len()),
            _ => return Err("search reply".into()),
        }
    }
}

#[wasm_bindgen]
pub async fn check_import(mode: &str) -> Result<String, JsValue> {
    let mut engine = Engine::default();
    let Output::Created(created) = command(
        &mut engine,
        Command::Create {
            name: "Public import probe".into(),
            password: PASSWORD.into(),
            remember: false,
        },
    )
    .await?
    else {
        return Err("create reply".into());
    };
    let id = created.info.id;
    if mode == "cancel" {
        let review = prepare_review(&mut engine, id, 64, "cancel").await?;
        let result = engine
            .apply_import(
                &mut BrowserStore,
                review.token,
                &choices(64, Action::Create),
                1,
                &mut Yield,
            )
            .await;
        require(
            result == Err(Error::Canceled),
            "worker cancellation was not observed",
        )?;
        require(
            size(id).await? == (0, 0),
            "cancellation left partial records",
        )?;
        command(&mut engine, Command::Lock).await?;
        return Ok(serde_json::json!({"canceled":true,"objects":0}).to_string());
    }
    require(mode == "atomic", "unknown check mode")?;
    let review = prepare_review(&mut engine, id, 2, "original").await?;
    require(size(id).await? == (0, 0), "review changed storage")?;
    let result = engine
        .apply_import(
            &mut BrowserStore,
            review.token,
            &choices(2, Action::Create),
            42,
            &mut Yield,
        )
        .await;
    require(
        result
            == Err(Error::App(AppError::Storage(
                confidex_storage::Error::Quota,
            ))),
        "expected injected quota error",
    )?;
    require(
        size(id).await? == (0, 0),
        "quota failure left partial records",
    )?;
    let review = prepare_review(&mut engine, id, 2, "original").await?;
    let report = engine
        .apply_import(
            &mut BrowserStore,
            review.token,
            &choices(2, Action::Create),
            42,
            &mut Yield,
        )
        .await
        .map_err(|error| JsValue::from_str(&format!("apply {error:?}")))?;
    require(
        report.added == 2 && size(id).await? == (2, 2),
        "retry did not commit the group",
    )?;
    require(
        search(&mut engine, "visible-wasm-needle").await? == 2,
        "public notes missing from search",
    )?;
    for text in ["private-wasm-secret-needle", "private-wasm-note-needle"] {
        require(
            search(&mut engine, text).await? == 0,
            "secret entered search",
        )?;
    }
    let review = prepare_review(&mut engine, id, 2, "original").await?;
    require(
        review
            .items
            .iter()
            .all(|item| item.matching == Match::Duplicate),
        "reimport created new identities",
    )?;
    engine
        .apply_import(
            &mut BrowserStore,
            review.token,
            &choices(2, Action::Skip),
            43,
            &mut Yield,
        )
        .await
        .map_err(|_| JsValue::from_str("skip"))?;
    require(size(id).await? == (2, 2), "skip changed storage")?;
    let review = prepare_review(&mut engine, id, 2, "concurrent").await?;
    let mut other = Engine::default();
    command(
        &mut other,
        Command::Unlock {
            vault: id,
            password: PASSWORD.into(),
            key: created.key.clone(),
            remember: false,
        },
    )
    .await?;
    let mut draft = confidex_app::new_record().map_err(|_| JsValue::from_str("record entropy"))?;
    draft.title = "Other writer".into();
    command(&mut other, Command::Save { draft, epoch: 44 }).await?;
    require(
        engine
            .apply_import(
                &mut BrowserStore,
                review.token,
                &choices(2, Action::Create),
                45,
                &mut Yield,
            )
            .await
            == Err(Error::App(AppError::Storage(
                confidex_storage::Error::Conflict,
            ))),
        "concurrent catalog change was overwritten",
    )?;
    require(size(id).await? == (3, 3), "conflict left partial records")?;
    command(&mut engine, Command::Lock).await?;
    let mut reopened = Engine::default();
    command(
        &mut reopened,
        Command::Unlock {
            vault: id,
            password: PASSWORD.into(),
            key: created.key.clone(),
            remember: false,
        },
    )
    .await?;
    let review = prepare_review(&mut reopened, id, 2, "original").await?;
    require(
        review
            .items
            .iter()
            .all(|item| item.matching == Match::Duplicate),
        "stored provenance did not reopen",
    )?;
    reopened
        .cancel_import(review.token)
        .map_err(|_| JsValue::from_str("cancel"))?;
    command(&mut reopened, Command::Lock).await?;
    Ok(serde_json::json!({"imported":2,"objects":3,"quotaRollback":true,"catalogConflict":true,"secretExcluded":true,"repeatSkipped":true,"reopened":true}).to_string())
}

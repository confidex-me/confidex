use crate::{browser_store::BrowserStore, cases, proof};
use confidex_storage::Store;
use wasm_bindgen::prelude::*;
struct Concurrent<'a> {
    created: &'a confidex_app::Created,
    fired: bool,
}
impl confidex_app::import_apply::Control for Concurrent<'_> {
    async fn checkpoint(&mut self, progress: confidex_app::import_apply::Progress) -> bool {
        if progress.phase == confidex_app::import_apply::Phase::Commit {
            assert!(!self.fired);
            proof::faults::write_concurrent(
                &mut BrowserStore,
                self.created.info.id,
                &self.created.key,
            )
            .await;
            self.fired = true;
        }
        true
    }
}
#[wasm_bindgen(
    inline_js = "export function integration_phase(name,phase) { self.postMessage({name,phase}); } export function integration_panic(error) { self.postMessage({error}); }
export function integration_quota(enabled) {
  return new Promise(resolve=>{
    const receive=({data})=>{if(data.quotaReady===enabled){self.removeEventListener('message',receive);resolve();}};
    self.addEventListener('message',receive);self.postMessage({quota:enabled});
  });
}
let add, inserts;
export function integration_insert_failure(enabled) {
  if(enabled) {
    add=IDBObjectStore.prototype.add;inserts=0;
    IDBObjectStore.prototype.add=function(...args){
      if(this.name==='objects'&&++inserts===2)throw new DOMException('Public quota fixture','QuotaExceededError');
      return add.apply(this,args);
    };
  } else {
    IDBObjectStore.prototype.add=add;
    if(inserts!==2)throw Error('The quota fixture did not interrupt the second object');
  }
}
export async function integration_wire(vault,revision,wire) {
  const hex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
  const key=[hex(vault),hex(revision)], copy=wire.slice();
  const db=await new Promise((resolve,reject)=>{
    const request=indexedDB.open('confidex',4);
    request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error);
  });
  try {
    await new Promise((resolve,reject)=>{
      const tx=db.transaction(['objects'],'readwrite'), objects=tx.objectStore('objects');
      tx.oncomplete=()=>resolve();tx.onabort=()=>reject(tx.error??Error('Missing test object'));
      const get=objects.get(key);
      get.onsuccess=()=>{const row=get.result;if(!row){tx.abort();return;}row.wire=copy;objects.put(row);};
    });
  } finally {db.close();}
}"
)]
extern "C" {
    fn integration_phase(name: &str, phase: &str);
    fn integration_panic(error: &str);
    fn integration_quota(enabled: bool) -> js_sys::Promise;
    fn integration_insert_failure(enabled: bool);
    fn integration_wire(vault: &[u8], revision: &[u8], wire: &[u8]) -> js_sys::Promise;
}
#[wasm_bindgen]
pub async fn check_kdbx_store() -> Result<String, JsValue> {
    std::panic::set_hook(Box::new(|info| integration_panic(&info.to_string())));
    let mut result = Vec::new();
    for case in cases::KDBX {
        integration_phase(case.name, "apply");
        let created = proof::first(&mut BrowserStore, case).await;
        integration_phase(case.name, "reopen");
        proof::reopened(&mut BrowserStore, case, &created).await;
        integration_phase(case.name, "changes");
        proof::changes::run(&mut BrowserStore, case, &created).await;
        BrowserStore.remove(created.info.id).await.unwrap();
        integration_phase(case.name, "done");
        result.push(
            serde_json::json!({"format":case.name,"items":case.total,"records":case.selected}),
        );
    }
    Ok(serde_json::to_string(&result).unwrap())
}
#[wasm_bindgen]
pub async fn check_integration() -> Result<String, JsValue> {
    std::panic::set_hook(Box::new(|info| integration_panic(&info.to_string())));
    let mut result = Vec::new();
    for case in cases::CASES.iter().chain(cases::KDBX) {
        integration_phase(case.name, "apply");
        let created = {
            let mut store = BrowserStore;
            proof::first(&mut store, case).await
        };
        integration_phase(case.name, "reopen");
        let mut store = BrowserStore;
        proof::reopened(&mut store, case, &created).await;
        integration_phase(case.name, "edits");
        proof::changes::run(&mut store, case, &created).await;
        store.remove(created.info.id).await.unwrap();
        result.push(
            serde_json::json!({"format":case.name,"items":case.total,"records":case.selected}),
        );
        integration_phase(case.name, "done");
    }
    for case in proof::service::cases() {
        integration_phase(case.name, "service");
        let mut store = BrowserStore;
        let created = proof::service::first(&mut store, case).await;
        proof::service::reopened(&mut store, case, &created).await;
        store.remove(created.info.id).await.unwrap();
        integration_phase(case.name, "service-done");
    }
    integration_phase("session-isolation", "start");
    let mut store = BrowserStore;
    for id in proof::service::isolation(&mut store).await {
        store.remove(id).await.unwrap();
    }
    integration_phase("session-isolation", "done");
    integration_phase("input-rejection", "start");
    let mut store = BrowserStore;
    let (created, expected) = proof::rejected::first(&mut store).await;
    proof::rejected::reopened(&mut store, &created, &expected).await;
    store.remove(created.info.id).await.unwrap();
    integration_phase("input-rejection", "done");
    integration_phase("concurrent", "start");
    let mut store = BrowserStore;
    let (mut engine, created) = proof::faults::setup(&mut store).await;
    let mut writer = Concurrent {
        created: &created,
        fired: false,
    };
    proof::faults::concurrent(&mut engine, &mut store, &created, &mut writer).await;
    assert!(writer.fired);
    store.remove(created.info.id).await.unwrap();
    integration_phase("concurrent", "done");
    let input = proof::faults::large_input();
    for real_quota in [false, true] {
        let name = if real_quota {
            "quota"
        } else {
            "insert-failure"
        };
        integration_phase(name, "start");
        let (mut engine, created) = proof::faults::setup(&mut store).await;
        proof::faults::write_concurrent(&mut store, created.info.id, &created.key).await;
        if real_quota {
            wasm_bindgen_futures::JsFuture::from(integration_quota(true)).await?;
        } else {
            integration_insert_failure(true);
        }
        let before = proof::faults::storage_failure(
            &mut engine,
            &mut store,
            &created,
            &input,
            confidex_storage::Error::Quota,
        )
        .await;
        if real_quota {
            wasm_bindgen_futures::JsFuture::from(integration_quota(false)).await?;
        } else {
            integration_insert_failure(false);
        }
        proof::faults::retry(&mut store, &created, &before, &input).await;
        store.remove(created.info.id).await.unwrap();
        integration_phase(name, "done");
    }
    integration_phase("index-recovery", "start");
    let case = &cases::CASES[0];
    let created = proof::first(&mut store, case).await;
    let id = created.info.id;
    let before = store.snapshot(id).await.unwrap();
    assert_eq!(before.heads.len(), 3);
    let target = before.heads.last().unwrap();
    let original = &before
        .objects
        .iter()
        .find(|object| object.head == *target)
        .unwrap()
        .wire;
    let mut engine = proof::index::open(&mut store, &created).await;
    let mut damaged = original.clone();
    *damaged.last_mut().unwrap() ^= 1;
    wasm_bindgen_futures::JsFuture::from(integration_wire(&id, &target.revision, &damaged)).await?;
    proof::index::failed(&mut engine, &mut store).await;
    wasm_bindgen_futures::JsFuture::from(integration_wire(&id, &target.revision, original)).await?;
    proof::index::recovered(&mut engine, &mut store, &created, &before).await;
    proof::reopened(&mut store, case, &created).await;
    store.remove(id).await.unwrap();
    integration_phase("index-recovery", "done");
    Ok(serde_json::to_string(&result).unwrap())
}

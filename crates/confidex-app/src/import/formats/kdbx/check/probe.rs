//! Public synthetic inputs only. This is not part of the production application.
mod allocator;
use confidex_app::import::{
    Context, Error, ErrorKind, Format, Limits, Options, Phase, Plan, formats::kdbx,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Serialize)]
pub struct Report {
    pub profile: u32,
    pub input: usize,
    pub records: usize,
    pub plan_bytes: usize,
    pub digest: String,
    pub error: Option<ErrorKind>,
    pub rust_peak: usize,
    pub realloc_upper_bound: usize,
    pub rust_retained: usize,
    pub rust_after_drop: usize,
    pub budget_released: bool,
    pub elapsed_ms: f64,
}

fn credentials(profile: u32) -> Options {
    let mut options = Options::default();
    options.source_instance = Some("PUBLIC-KDBX-PROBE".into());
    let password = match profile {
        0 | 2 | 19 | 20 => "PUBLIC-FIXTURE-DATABASE",
        3..=5 | 14 => "PUBLIC-VARIANT-DATABASE",
        8 | 9 => "demopass",
        10 | 12 | 13 => "PUBLIC-BENCH-DATABASE",
        11 => "PUBLIC-WRONG-PASSWORD",
        _ => "",
    };
    options.password = password.into();
    options.keyfile = match profile {
        1 | 2 | 16..=18 => include_bytes!(concat!(
            env!("CONFIDEX_ROOT"),
            "/crates/confidex-app/tests/import_fixtures/kdbx/public.key"
        ))
        .to_vec(),
        5 => include_bytes!(concat!(
            env!("CONFIDEX_ROOT"),
            "/vendor/keepass/tests/resources/bounded/public-v2.keyx"
        ))
        .to_vec(),
        6 => include_bytes!(concat!(
            env!("CONFIDEX_ROOT"),
            "/vendor/keepass/tests/resources/bounded/public.raw"
        ))
        .to_vec(),
        7 => include_bytes!(concat!(
            env!("CONFIDEX_ROOT"),
            "/vendor/keepass/tests/resources/bounded/public.hex"
        ))
        .to_vec(),
        _ => Vec::new(),
    };
    options.password_present = !matches!(profile, 1 | 6 | 7 | 17 | 20);
    options.keyfile_present = matches!(profile, 1 | 2 | 5 | 6 | 7 | 16..=19);
    options
}

fn fingerprint(plan: &Plan) -> String {
    fn part(hash: &mut Sha256, bytes: &[u8]) {
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    let mut hash = Sha256::new();
    for item in &plan.items {
        part(&mut hash, item.record_bytes());
        part(&mut hash, item.source_attributes_bytes());
        part(&mut hash, &serde_json::to_vec(&item.source).unwrap());
        part(&mut hash, &serde_json::to_vec(&item.status).unwrap());
        part(&mut hash, &serde_json::to_vec(&item.diagnostics).unwrap());
    }
    part(
        &mut hash,
        plan.container_attributes_bytes().unwrap_or_default(),
    );
    part(
        &mut hash,
        &serde_json::to_vec(&plan.container_status).unwrap(),
    );
    part(
        &mut hash,
        &serde_json::to_vec(&plan.container_diagnostics).unwrap(),
    );
    use std::fmt::Write as _;
    let mut digest = String::with_capacity(64);
    for byte in hash.finalize() {
        write!(&mut digest, "{byte:02x}").unwrap();
    }
    digest
}

#[cfg(target_arch = "wasm32")]
thread_local! {
    static CANCEL: std::cell::RefCell<Option<js_sys::Int32Array>> = const { std::cell::RefCell::new(None) };
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn set_cancel_flag(flag: js_sys::Int32Array) {
    CANCEL.with(|state| *state.borrow_mut() = Some(flag));
}

fn signaled() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        CANCEL.with(|state| {
            state.borrow().as_ref().is_some_and(|flag| {
                js_sys::Atomics::add(flag, 1, 1).unwrap();
                js_sys::Atomics::load(flag, 0).unwrap() != 0
            })
        })
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        false
    }
}

fn clock() -> f64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64()
            * 1000.0
    }
}

pub fn perform(input: Vec<u8>, profile: u32) -> Report {
    let input = Zeroizing::new(input);
    let baseline = allocator::live().saturating_sub(input.capacity());
    allocator::verify();
    allocator::reset();
    let started = clock();
    let options = credentials(profile);
    let limits = Limits::default();
    let mut budget = None;
    let result = (|| -> Result<Plan, Error> {
        let mut check = |progress: confidex_app::import::Progress| {
            !signaled()
                && !(profile == 12 && progress.phase == Phase::Read
                    || profile == 13
                        && progress.phase == Phase::Validate
                        && progress.current >= 5000)
        };
        let mut context = Context::new(Format::Kdbx, input.len(), &options, limits, &mut check)?;
        budget = Some(context.memory().clone());
        kdbx::parse(&input, &mut context)?;
        context.finish()
    })();
    let retained = allocator::live().saturating_sub(baseline);
    let (records, bytes, digest, error) = match &result {
        Ok(plan) => (
            plan.items.len(),
            plan.statistics.encoded_bytes,
            fingerprint(plan),
            None,
        ),
        Err(error) => (0, 0, String::new(), Some(error.kind)),
    };
    let peak = allocator::peak().saturating_sub(baseline);
    let overlap = allocator::overlap().saturating_sub(baseline);
    let elapsed = clock() - started;
    let input_len = input.len();
    drop(result);
    drop(options);
    drop(input);
    let budget_released = budget
        .as_ref()
        .is_none_or(|m| m.available() == limits.memory_bytes);
    drop(budget);
    let after = allocator::live()
        .saturating_sub(baseline)
        .saturating_sub(digest.capacity());
    assert!(budget_released);
    assert!(
        overlap < limits.memory_bytes,
        "Import allocator peak exceeds its budget"
    );
    Report {
        profile,
        input: input_len,
        records,
        plan_bytes: bytes,
        digest,
        error,
        rust_peak: peak,
        realloc_upper_bound: overlap,
        rust_retained: retained,
        rust_after_drop: after,
        budget_released,
        elapsed_ms: elapsed,
    }
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn run_case(input: Vec<u8>, profile: u32) -> String {
    serde_json::to_string(&perform(input, profile)).unwrap()
}

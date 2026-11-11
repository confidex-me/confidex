use super::proof;
use confidex_storage::Store;
#[path = "performance/store.rs"]
mod measured;
#[path = "performance/timing.rs"]
mod timing;

pub async fn first<S: Store>(
    store: &mut S,
    progress: &mut impl FnMut(&'static str),
) -> (confidex_app::Created, timing::Summary) {
    let mut store = measured::Measured {
        inner: store,
        commit_ms: 0.0,
    };
    let mut timing = timing::Timing::new();
    let created = proof::first_load_observed(&mut store, &mut |event| {
        timing.observe(event);
        if let proof::LoadEvent::Boundary(phase) = event {
            progress(phase);
        }
    })
    .await;
    let report = timing.finish(store.commit_ms);
    assert!(report.parse_checkpoints[1] > crate::load::ROWS);
    assert_eq!(report.parse_checkpoints[2], crate::load::ROWS * 11);
    assert!(report.commit_ms > 0.0);
    (created, report)
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
#[ignore = "Run explicitly in release mode for stage timings and process memory"]
fn ten_thousand_stages() {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("profile.sqlite");
            let mut store = confidex_storage::SqliteStore::open(&path).unwrap();
            let (created, report) = first(&mut store, &mut |phase| {
                println!("csv-profile phase={phase}")
            })
            .await;
            drop(store);
            let mut store = confidex_storage::SqliteStore::open(&path).unwrap();
            proof::reopened_load(&mut store, &created, &mut |phase| {
                println!("csv-profile phase={phase}")
            })
            .await;
            println!("csv-profile {}", serde_json::to_string(&report).unwrap());
        });
}

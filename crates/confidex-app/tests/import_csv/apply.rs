#[path = "performance.rs"]
mod performance;
#[path = "proof.rs"]
mod proof;
use confidex_storage::SqliteStore;

#[test]
fn real_csv_apply_reopen_search_and_repeat_use_content_instead_of_row_or_title_identity() {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("public-csv.sqlite");
            let mut store = SqliteStore::open(&path).unwrap();
            let created = proof::first(&mut store).await;
            drop(store);
            let mut store = SqliteStore::open(&path).unwrap();
            proof::reopened(&mut store, &created).await;
        });
}

#[test]
#[ignore = "Run separately for the complete 10000-record encrypted storage workload"]
fn ten_thousand_rows_parse_apply_reopen_search_and_repeat() {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("public-csv-load.sqlite");
            let started = std::time::Instant::now();
            let mut progress = |phase| {
                println!(
                    "csv-load phase={phase} elapsed_ms={}",
                    started.elapsed().as_millis()
                )
            };
            let mut store = SqliteStore::open(&path).unwrap();
            let created = proof::first_load(&mut store, &mut progress).await;
            drop(store);
            let mut store = SqliteStore::open(&path).unwrap();
            proof::reopened_load(&mut store, &created, &mut progress).await;
            println!(
                "csv-full-10k records=10000 elapsed_ms={}",
                started.elapsed().as_millis()
            );
        });
}

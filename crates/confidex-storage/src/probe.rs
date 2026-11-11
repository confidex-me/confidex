#[cfg(not(target_arch = "wasm32"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use confidex_storage::{Head, SqliteStore, Store, StoredVault, VaultInfo};
    use std::io::{self, Write};
    let args: Vec<_> = std::env::args().collect();
    let mut store = SqliteStore::open(std::path::Path::new(
        args.get(1).ok_or("database path required")?,
    ))
    .map_err(|e| format!("{e:?}"))?;
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    runtime
        .block_on(async {
            match args.get(2).map(String::as_str) {
                Some("init") => {
                    store
                        .create(&StoredVault {
                            info: VaultInfo {
                                id: [1; 16],
                                name: "fixture".into(),
                            },
                            lock: vec![1],
                        })
                        .await
                }
                Some("race") => {
                    let old = store.head([1; 16], [2; 16]).await?;
                    println!("ready:{}", std::process::id());
                    io::stdout()
                        .flush()
                        .map_err(|_| confidex_storage::Error::Storage)?;
                    let mut line = String::new();
                    io::stdin()
                        .read_line(&mut line)
                        .map_err(|_| confidex_storage::Error::Storage)?;
                    let value = args
                        .get(3)
                        .and_then(|v| v.parse::<u8>().ok())
                        .ok_or(confidex_storage::Error::Invalid)?;
                    let result = store
                        .append(
                            [1; 16],
                            &Head {
                                record: [2; 16],
                                revision: [value; 32],
                            },
                            old.map(|v| v.revision),
                            &[value],
                            &[],
                        )
                        .await;
                    println!("{result:?}");
                    Ok(())
                }
                Some("list") => {
                    println!("{}", store.vaults().await?.len());
                    Ok(())
                }
                _ => Err(confidex_storage::Error::Invalid),
            }
        })
        .map_err(|e| format!("{e:?}"))?;
    Ok(())
}
#[cfg(target_arch = "wasm32")]
fn main() {}

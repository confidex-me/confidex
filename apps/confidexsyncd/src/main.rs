#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use confidexsyncd::{config::Config, native::Index};
    let mut args = std::env::args().skip(1);
    let config = match args.next().as_deref() {
        Some("--version") => {
            println!("confidexsyncd {}", confidex_vault::BUILD_VERSION);
            return Ok(());
        }
        Some("--help") => {
            println!(
                "Usage: confidexsyncd [CONFIG_TOML]\nWithout a file, read LISTEN_*, INDEX_URL, LIMITS_BODY_BYTES and BACKEND_* from the environment."
            );
            return Ok(());
        }
        Some(path) => toml::from_str::<Config>(&std::fs::read_to_string(path)?)?,
        None => Config::from_env()?,
    };
    if args.next().is_some() {
        return Err("Expected one configuration file".into());
    }
    let socket = config.socket();
    let limits = config
        .limits
        .validate()
        .map_err(|_| "limits.body_bytes must be between 1 and 8000000")?;
    let index = Index::open(&config.index.url)
        .await
        .map_err(|_| "Cannot open sync index")?;
    let blobs = config
        .destinations()
        .map_err(|_| "Cannot open object backends")?;
    let listener = tokio::net::TcpListener::bind(socket).await?;
    eprintln!("confidexsyncd listening on {}", listener.local_addr()?);
    axum::serve(
        listener,
        confidexsyncd::native::router(index, blobs, limits),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}
#[cfg(target_arch = "wasm32")]
fn main() {}

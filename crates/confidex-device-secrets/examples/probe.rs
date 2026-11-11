use confidex_device_secrets::*;
fn main() {
    #[cfg(not(target_arch = "wasm32"))]
    if let Err(error) = futures_executor::block_on(run()) {
        eprintln!("backend probe: {error}");
        std::process::exit(1)
    }
}
#[cfg(not(target_arch = "wasm32"))]
async fn run() -> Result<()> {
    let namespace = std::env::args().nth(1).ok_or(Error::InvalidData)?;
    if !namespace.starts_with("dev.confidex.test.") {
        return Err(Error::InvalidData);
    }
    let id = SecretId {
        vault: [0xa5; 16],
        purpose: Purpose::SecretKey,
    };
    let secret = SecretBytes::new(b"public-device-secret-fixture".to_vec())?;
    let mode = std::env::args().nth(2);
    if mode.as_deref() == Some("--read-cleanup") {
        let mut device = platform::system(&namespace)?;
        assert_eq!(
            device.get(id, Interaction::Forbid).await?.expose(),
            secret.expose()
        );
        device.remove(id, Interaction::Forbid).await?;
        #[cfg(feature = "backend-check")]
        {
            let (_, mut protector) = device.into_backends();
            protector.cleanup()?;
        }
        println!("cross-process persistence and removal: pass");
        return Ok(());
    }
    let mut protector = platform::Protector::new(&namespace)?;
    let binding = Binding::new(&namespace, id, AccessPolicy::DeviceBound)?;
    let key = Secret32::new([0x5a; 32]);
    println!(
        "protector capabilities: {:?}",
        protector.capabilities().await?
    );
    let sealed = protector
        .seal_key(
            &binding,
            &key,
            AccessPolicy::DeviceBound,
            Interaction::Forbid,
        )
        .await?;
    assert_eq!(
        protector
            .unseal_key(
                &binding,
                &sealed,
                AccessPolicy::DeviceBound,
                Interaction::Forbid
            )
            .await?
            .expose(),
        key.expose()
    );
    let wrong = Binding::new("dev.confidex.test.other", id, AccessPolicy::DeviceBound)?;
    assert!(
        protector
            .unseal_key(
                &wrong,
                &sealed,
                AccessPolicy::DeviceBound,
                Interaction::Forbid
            )
            .await
            .is_err()
    );
    let mut protector = platform::Protector::new(&namespace)?;
    assert_eq!(
        protector
            .unseal_key(
                &binding,
                &sealed,
                AccessPolicy::DeviceBound,
                Interaction::Forbid
            )
            .await?
            .expose(),
        key.expose()
    );
    println!("protector roundtrip, binding rejection, reopen: pass");
    if std::env::args().nth(2).as_deref() == Some("--protector-only") {
        #[cfg(feature = "backend-check")]
        protector.cleanup()?;
        return Ok(());
    }
    let mut device = platform::system(&namespace)?;
    println!("capabilities: {:?}", device.capabilities().await?);
    device
        .put(id, &secret, AccessPolicy::DeviceBound, Interaction::Forbid)
        .await?;
    if mode.as_deref() == Some("--write") {
        println!("cross-process fixture stored");
        return Ok(());
    }
    assert_eq!(
        device.inspect(id).await?,
        EntryState::Stored {
            policy: AccessPolicy::DeviceBound
        }
    );
    assert_eq!(
        device.get(id, Interaction::Forbid).await?.expose(),
        secret.expose()
    );
    drop(device);
    let mut device = platform::system(&namespace)?;
    assert_eq!(
        device.get(id, Interaction::Forbid).await?.expose(),
        secret.expose()
    );
    let replacement = SecretBytes::new(b"public-device-secret-replacement".to_vec())?;
    device
        .put(
            id,
            &replacement,
            AccessPolicy::DeviceBound,
            Interaction::Forbid,
        )
        .await?;
    assert_eq!(
        device.get(id, Interaction::Forbid).await?.expose(),
        replacement.expose()
    );
    device.remove(id, Interaction::Forbid).await?;
    assert_eq!(device.inspect(id).await?, EntryState::Missing);
    #[cfg(feature = "backend-check")]
    {
        let (_, mut protector) = device.into_backends();
        protector.cleanup()?;
    }
    println!("roundtrip, reopen, replacement, removal: pass");
    Ok(())
}

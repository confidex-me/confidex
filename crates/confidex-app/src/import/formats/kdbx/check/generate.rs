//! Generate a public 10k workload. Its allocations are outside import measurements.
use keepass::{
    Database, DatabaseKey,
    config::{DatabaseConfig, DatabaseVersion, KdfConfig},
    db::Value,
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os().nth(1).ok_or("output path required")?;
    let mut config = DatabaseConfig::default();
    config.version = DatabaseVersion::KDB4(1);
    config.kdf_config = KdfConfig::Argon2id {
        memory: 64 << 20,
        iterations: 3,
        parallelism: 1,
        version: 0x13.try_into()?,
    };
    let mut db = Database::with_config(config);
    for index in 0..10_000 {
        db.root_mut().add_entry().edit(|entry| {
            entry.set_unprotected("Title", format!("PUBLIC-BENCH-{index:05}"));
            entry.set_unprotected("UserName", format!("public-{index:05}"));
            entry.set_unprotected("URL", "https://public.example.invalid/");
            entry.set_protected("Password", "PUBLIC-BENCH-PASSWORD");
            entry.set_protected("Custom secret", "PUBLIC-BENCH-SECRET");
            entry.set_protected("Notes", "PUBLIC-BENCH-NOTE\nSecond line");
            if index % 1000 == 0 {
                entry.add_attachment(
                    "public.bin",
                    Value::protected(b"PUBLIC-BENCH-ATTACHMENT\0\xff".to_vec()),
                );
            }
        });
    }
    db.save(
        &mut std::fs::File::create(path)?,
        DatabaseKey::new().with_password("PUBLIC-BENCH-DATABASE"),
    )?;
    Ok(())
}

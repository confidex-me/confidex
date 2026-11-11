//! Independent public-fixture check with the unmodified registry keepass 0.17.0.
use keepass::{Database, DatabaseKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("KDBX path required")?;
    let database = Database::parse(
        &std::fs::read(path)?,
        DatabaseKey::new().with_password("PUBLIC-VARIANT-DATABASE"),
    )?;
    assert_eq!(database.num_entries(), 1);
    let root = database.root();
    let entry = root.entry_by_name("PUBLIC-VECTOR").ok_or("entry missing")?;
    assert_eq!(entry.get_password(), Some("PUBLIC-VARIANT-PASSWORD"));
    println!("Registry keepass 0.17.0 / rust-argon2: Argon2 v1.0 container PASS");
    Ok(())
}

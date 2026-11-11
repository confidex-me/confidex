//! Create an independent vault with public data for screenshots.
use confidex_app::{Command, DeviceKeys, Engine, Output, Request, backup};
use confidex_storage::{Head, Snapshot, SqliteStore, Store, StoredObject, StoredVault, VaultInfo};
use confidex_vault::{
    entropy, envelope, kdf, lock,
    record::{Entry, Mapping, Record, Value},
    resources::MAX_OPEN_MEMORY,
    ssh, transfer_code,
};
use std::{collections::BTreeSet, fmt::Debug, fs, io, path::Path, time::SystemTime};

const PASSWORD: &str = "Demo-Screenshots-2026!";
const NAME: &str = "Demo · Screenshots";

fn checked<T, E: Debug>(result: Result<T, E>) -> io::Result<T> {
    result.map_err(|error| io::Error::other(format!("{error:?}")))
}
fn protected(mut entry: Entry) -> Entry {
    entry.extra.insert(
        "metadata".into(),
        Value::Map(vec![("protected".into(), true.into())]),
    );
    entry
}
fn value(name: &str, kind: &str, key: &str, text: &str) -> Entry {
    let entry = Entry {
        name: name.into(),
        type_name: kind.into(),
        value: Mapping::from([(key.into(), text.into())]),
        extra: Mapping::new(),
    };
    if matches!(kind, "password/v1" | "secret/v1" | "secure-note/v1") {
        protected(entry)
    } else {
        entry
    }
}
fn text(name: &str, content: &str) -> Entry {
    value(name, "text/v1", "text", content)
}
fn password(name: &str, content: &str) -> Entry {
    value(name, "password/v1", "password", content)
}
fn note(content: &str) -> Entry {
    value("Notes", "note/v1", "text", content)
}
fn secret(name: &str, content: &str) -> Entry {
    value(name, "secret/v1", "secret", content)
}
fn url(content: &str) -> Entry {
    value("Website", "url/v1", "url", content)
}
fn otp() -> Entry {
    protected(Entry {
        name: "Authenticator".into(),
        type_name: "totp/v1".into(),
        value: Mapping::from([
            (
                "secret".into(),
                Value::Binary(b"12345678901234567890".to_vec()),
            ),
            ("algorithm".into(), "SHA1".into()),
            ("digits".into(), 6u64.into()),
            ("period".into(), 30u64.into()),
            ("t0".into(), 0u64.into()),
        ]),
        extra: Mapping::new(),
    })
}
fn record(title: &str, tags: &[&str], entries: Vec<Entry>) -> Record {
    let mut tags: Vec<_> = tags.iter().map(|s| (*s).to_owned()).collect();
    tags.sort();
    tags.dedup();
    Record {
        entries,
        tags,
        extra: Mapping::from([("confidex.title".into(), title.into())]),
    }
}
fn login(title: &str, site: &str, user: &str, pass: &str, tags: &[&str]) -> Record {
    record(
        title,
        tags,
        vec![
            value("Username", "username/v1", "username", user),
            password("Password", pass),
            url(site),
            otp(),
            note("Personal account. Recovery codes are stored separately."),
        ],
    )
}
fn records(jpeg: Vec<u8>, webp: Vec<u8>) -> io::Result<Vec<Record>> {
    let mut output = vec![
        login(
            "GitHub",
            "https://github.com",
            "alex.morgan",
            "Maple!Compass-48-River",
            &["Work", "Development"],
        ),
        login(
            "Proton Mail",
            "https://mail.proton.me",
            "alex.morgan@example.test",
            "Copper!Lantern-72-Paper",
            &["Personal", "Email"],
        ),
        login(
            "Figma",
            "https://figma.com",
            "alex@studio.example.test",
            "Velvet!Studio-63-Moon",
            &["Work", "Design"],
        ),
        login(
            "Cloudflare",
            "https://dash.cloudflare.com",
            "alex@studio.example.test",
            "Cedar!Harbour-51-Cloud",
            &["Work", "Infrastructure"],
        ),
        login(
            "Dropbox",
            "https://dropbox.com",
            "alex.morgan@example.test",
            "Pebble!Forest-34-Atlas",
            &["Personal", "Storage"],
        ),
        login(
            "Booking.com",
            "https://booking.com",
            "alex.morgan@example.test",
            "Amber!Journey-26-North",
            &["Personal", "Travel"],
        ),
        record(
            "Visa · Everyday",
            &["Finance", "Personal"],
            vec![
                text("Cardholder", "ALEX MORGAN"),
                secret("Card number", "4242 4242 4242 4242"),
                text("Expires", "08/2030"),
                password("Security code", "123"),
                password("PIN", "4056"),
                text("Bank", "Northstar Bank"),
                note(
                    "Everyday spending · EUR\nContactless payments enabled.\nFictional card for screenshots.",
                ),
            ],
        ),
        record(
            "Mastercard · Studio",
            &["Finance", "Work"],
            vec![
                text("Cardholder", "MORGAN STUDIO"),
                secret("Card number", "5555 5555 5555 4444"),
                text("Expires", "03/2031"),
                password("Security code", "456"),
                text(
                    "Billing address",
                    "24 Canal Street\n1015 AB Amsterdam\nThe Netherlands",
                ),
                note("Studio subscriptions and software licences."),
            ],
        ),
        record(
            "Home Wi-Fi",
            &["Home", "Networks"],
            vec![
                text("Network name", "Atelier Home"),
                password("Password", "Cinnamon-Cloud-47"),
                text("Security", "WPA2 / WPA3"),
                text("Router", "192.168.1.1"),
                protected(Entry {
                    name: "Wi-Fi credentials".into(),
                    type_name: "wifi/v1".into(),
                    value: Mapping::from([
                        ("ssid".into(), "Atelier Home".into()),
                        ("auth".into(), "WPA".into()),
                        ("password".into(), "Cinnamon-Cloud-47".into()),
                        ("hidden".into(), false.into()),
                    ]),
                    extra: Mapping::new(),
                }),
                note("Guest network is separate from the home office."),
            ],
        ),
        record(
            "Guest Wi-Fi",
            &["Home", "Networks"],
            vec![
                text("Network name", "Atelier Guest"),
                password("Password", "Welcome-Orange-28"),
                text("Security", "WPA2"),
                note("For friends and visiting family.\nInternet access only."),
            ],
        ),
        record(
            "Studio API",
            &["Work", "Development"],
            vec![
                secret("API key", "sk_demo_6db4ac72e18f4e36b623abf158ad0932"),
                secret("Webhook signing secret", "DEMO-ONLY-HIDDEN-TOKEN"),
                url("https://api.example.test/v1"),
                text("Environment", "Staging"),
                text("Permissions", "Read projects · Create previews"),
                note(
                    "Used by the studio preview environment.\nRotate together with the deployment credentials.",
                ),
            ],
        ),
        record(
            "Recovery codes",
            &["Personal", "Security"],
            vec![
                value(
                    "Account",
                    "username/v1",
                    "username",
                    "alex.morgan@example.test",
                ),
                value(
                    "Backup codes",
                    "secure-note/v1",
                    "text",
                    "A4E8-9B21\nC7D2-5F60\nE3A9-8C14\nB6F1-2D75\nD9C4-7A03",
                ),
                note("One-time recovery codes. All values in this vault are fictional."),
            ],
        ),
        record(
            "Amsterdam weekend",
            &["Personal", "Travel"],
            vec![
                text("Hotel", "The Canal House"),
                text("Address", "18 Lindenstraat, Amsterdam"),
                text("Reservation", "DEMO-AMS-2048"),
                text("Check-in", "Friday · 15:00"),
                text("Check-out", "Monday · 11:00"),
                password("Door code", "2846#"),
                note(
                    "Friday\n• Coffee by the canal\n• Check in after 15:00\n\nSaturday\n• Visit the museum\n• Dinner at 19:30\n\nBring the booking confirmation and a light raincoat.",
                ),
            ],
        ),
        record(
            "Private journal",
            &["Personal", "Notes"],
            vec![
                value(
                    "Journal",
                    "secure-note/v1",
                    "text",
                    "A quiet morning, a fresh notebook, and no meetings until lunch.\n\nFinish the first draft, take a walk along the water, and make room for the next idea.",
                ),
                note("Private notes stay out of search."),
            ],
        ),
        record(
            "Software licences",
            &["Work", "Documents"],
            vec![
                text("Product", "Northstar Studio Pro"),
                secret("Licence key", "DEMO-4F8A-72BC-901D-E63F"),
                text("Registered to", "Morgan Studio"),
                text("Seats", "3 devices"),
                text("Renewal", "12 September 2027"),
                url("https://studio.example.test/account"),
                note("Annual studio subscription. Includes desktop and mobile."),
            ],
        ),
        record(
            "Emergency contacts",
            &["Home", "Personal"],
            vec![
                text("Contact", "Jordan Morgan"),
                text("Phone", "+1 202 555 0148"),
                text("Email", "jordan@example.test"),
                text("Address", "24 Canal Street\nAmsterdam"),
                value(
                    "Private instructions",
                    "secure-note/v1",
                    "text",
                    "The spare key is in the blue envelope.\nAll names, addresses and instructions are invented.",
                ),
                note("Keep a printed copy with the travel documents."),
            ],
        ),
    ];
    let fixture: serde_json::Value = checked(serde_json::from_str(include_str!(
        "../tests/import_fixtures/bitwarden_json/ssh-key.json"
    )))?;
    let source = &fixture["items"][0]["sshKey"];
    let key = checked(ssh::Key::import(
        source["privateKey"].as_str().unwrap().as_bytes(),
        None,
        MAX_OPEN_MEMORY,
    ))?;
    output.push(record(
        "SSH · Studio server",
        &["Work", "Infrastructure"],
        vec![
            text("Host", "studio.example.test"),
            value("Username", "username/v1", "username", "deploy"),
            text("Port", "22"),
            text("Public key", source["publicKey"].as_str().unwrap()),
            protected(Entry {
                name: "Ed25519 private key".into(),
                type_name: "ssh/v1".into(),
                value: checked(key.to_value())?,
                extra: Mapping::new(),
            }),
            note("Public test key. Never use it for a real server."),
        ],
    ));
    output.push(record("Identity card · Foma Kinaev", &["Personal", "Documents"], vec![text("Full name", "Foma Kinaev"), text("Document number", "DEMO-4072-5186"), text("Date of birth", "21 August 1969"), text("Document", "Fictional film prop"), protected(Entry { name: "Document photograph".into(), type_name: "photo/v1".into(), value: Mapping::from([("mime".into(), "image/webp".into()), ("data".into(), Value::Binary(webp))]), extra: Mapping::new() }), protected(Entry { name: "Original JPEG".into(), type_name: "file/v1".into(), value: Mapping::from([("mime".into(), "image/jpeg".into()), ("filename".into(), "foma-kinaev-id.jpg".into()), ("data".into(), Value::Binary(jpeg))]), extra: Mapping::new() }), note("Film still supplied for this screenshot vault.\nThis is a fictional document, not a real identity record.")]));
    Ok(output)
}

struct NoKeys;
impl DeviceKeys for NoKeys {
    async fn remove(&mut self, _: [u8; 16]) -> bool {
        true
    }
    async fn load(&mut self, _: [u8; 16]) -> Option<String> {
        None
    }
    async fn save(&mut self, _: [u8; 16], _: &str) -> bool {
        false
    }
}
async fn command(
    engine: &mut Engine,
    store: &mut SqliteStore,
    command: Command,
) -> io::Result<Output> {
    checked(
        engine
            .execute(
                store,
                &mut NoKeys,
                &mut Request {
                    generation: 1,
                    command,
                },
            )
            .await
            .result,
    )
}
fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
async fn create(database: &Path, directory: &Path, jpeg: &Path, webp: &Path) -> io::Result<()> {
    fs::create_dir_all(directory)?;
    for name in ["credentials.txt", "demo-vault.zip", "demo.sqlite"] {
        if directory.join(name).exists() {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, name));
        }
    }
    if fs::metadata(jpeg)?.len() > 4_000_000 || fs::metadata(webp)?.len() > 4_000_000 {
        return Err(io::Error::other("document is too large"));
    }
    let photo = fs::read(webp)?;
    if !photo.starts_with(b"RIFF") || photo.get(8..12) != Some(b"WEBP") {
        return Err(io::Error::other("expected WebP"));
    }
    let records = records(fs::read(jpeg)?, photo)?;
    let fields: usize = records.iter().map(|record| record.entries.len()).sum();
    let mut kinds = BTreeSet::new();
    for record in &records {
        for entry in &record.entries {
            checked(entry.validate_value())?;
            kinds.insert(entry.type_name.clone());
        }
    }
    let created = checked(lock::create(PASSWORD.as_bytes(), kdf::REQUIRED_MEMORY))?;
    let id = created.vault.vault_id();
    let key = transfer_code::encode(
        &created.vault.keys().secret_key(),
        &created.vault.anchor().public_key(),
    );
    let key = checked(std::str::from_utf8(&key[..]))?;
    let epoch = checked(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH))?.as_secs();
    let mut objects = Vec::new();
    for record in &records {
        let mut record_id = [0; 16];
        checked(entropy::fill_random(&mut record_id))?;
        let wire = checked(envelope::seal(
            record,
            created.vault.keys(),
            envelope::Options {
                vault_id: id,
                record_id,
                parents: &[],
                epoch,
                kind: envelope::EventKind::Content,
            },
            MAX_OPEN_MEMORY,
        ))?;
        let revision = checked(envelope::verify(
            &wire,
            created.vault.anchor(),
            None,
            MAX_OPEN_MEMORY,
        ))?
        .id();
        let opened = checked(envelope::open(
            &wire,
            created.vault.keys(),
            created.vault.anchor(),
            Some(&revision),
            MAX_OPEN_MEMORY,
        ))?;
        assert!(
            checked(opened.record.encode_content(MAX_OPEN_MEMORY))?.bytes
                == checked(record.encode_content(MAX_OPEN_MEMORY))?.bytes,
            "record round-trip"
        );
        objects.push(StoredObject {
            head: Head {
                record: record_id,
                revision,
            },
            wire,
            tags: record.tags.clone(),
        });
    }
    let mut heads: Vec<_> = objects.iter().map(|object| object.head.clone()).collect();
    heads.sort_by_key(|head| head.record);
    let snapshot = Snapshot {
        vault: StoredVault {
            info: VaultInfo {
                id,
                name: NAME.into(),
            },
            lock: created.lock,
        },
        objects,
        heads,
    };
    checked(snapshot.validate())?;
    let mut local = checked(SqliteStore::open(&directory.join("demo.sqlite")))?;
    checked(local.restore(&snapshot).await)?;
    let zip = checked(backup::export(&mut local, &created.vault).await)?;
    let (restored, _) = checked(backup::restore(&zip, NAME, PASSWORD, key))?;
    assert_eq!(restored.heads, snapshot.heads);
    assert_eq!(restored.objects.len(), records.len());
    let mut engine = Engine::default();
    command(
        &mut engine,
        &mut local,
        Command::Unlock {
            vault: id,
            password: PASSWORD.into(),
            key: key.into(),
            remember: false,
        },
    )
    .await?;
    for (query, expected) in [("GitHub", 1), ("DEMO-ONLY-HIDDEN-TOKEN", 0)] {
        loop {
            match command(
                &mut engine,
                &mut local,
                Command::Search {
                    query: query.into(),
                    after: None,
                    tag: None,
                    refresh: false,
                },
            )
            .await?
            {
                Output::Indexing => (),
                Output::Rows { rows, .. } => {
                    assert_eq!(rows.len(), expected);
                    break;
                }
                _ => return Err(io::Error::other("unexpected search reply")),
            }
        }
    }
    write_new(&directory.join("demo-vault.zip"), &zip)?;
    write_new(&directory.join("credentials.txt"), format!("Vault: {NAME}\nPassword: {PASSWORD}\nsecret_key: {key}\n\nAll credentials are fictional and for screenshots only.\nSync is disabled.\n").as_bytes())?;
    let mut installed = checked(SqliteStore::open(database))?;
    let before: Vec<_> = checked(installed.vaults().await)?
        .into_iter()
        .map(|v| (v.id, v.name))
        .collect();
    checked(installed.restore(&snapshot).await)?;
    let after: Vec<_> = checked(installed.vaults().await)?
        .into_iter()
        .map(|v| (v.id, v.name))
        .collect();
    assert_eq!(after.len(), before.len() + 1);
    assert!(before.iter().all(|vault| after.contains(vault)));
    println!(
        "Created screenshot vault: {} records, {fields} fields, {} field types; backup verified; existing vaults preserved",
        records.len(),
        kinds.len()
    );
    Ok(())
}
fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 4 {
        return Err(io::Error::other(
            "usage: demo_vault DATABASE OUTPUT_DIRECTORY DOCUMENT_JPEG DOCUMENT_WEBP",
        ));
    }
    tokio::runtime::Builder::new_current_thread()
        .build()?
        .block_on(create(
            Path::new(&args[0]),
            Path::new(&args[1]),
            Path::new(&args[2]),
            Path::new(&args[3]),
        ))
}

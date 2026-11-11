//! Public synthetic variant producer; requires the local keepass save_kdbx4 feature.
use keepass::{config::*, db::Value, Database, DatabaseKey};
use std::{fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .ok_or("output directory required")?,
    );
    let argon = |id: bool, version: u32| -> Result<KdfConfig, Box<dyn std::error::Error>> {
        Ok(if id {
            KdfConfig::Argon2id {
                memory: 65536,
                iterations: 2,
                parallelism: 2,
                version: version.try_into()?,
            }
        } else {
            KdfConfig::Argon2 {
                memory: 65536,
                iterations: 2,
                parallelism: 2,
                version: version.try_into()?,
            }
        })
    };
    for (name, minor, cipher, inner, compression, kdf, keyfile, password) in [
        (
            "argon2d-aes-v10",
            1,
            OuterCipherConfig::AES256,
            InnerCipherConfig::Salsa20,
            CompressionConfig::GZip,
            argon(false, 0x10)?,
            None,
            true,
        ),
        (
            "argon2d-aes",
            1,
            OuterCipherConfig::AES256,
            InnerCipherConfig::Salsa20,
            CompressionConfig::GZip,
            argon(false, 0x13)?,
            None,
            true,
        ),
        (
            "argon2id-chacha",
            1,
            OuterCipherConfig::ChaCha20,
            InnerCipherConfig::ChaCha20,
            CompressionConfig::GZip,
            argon(true, 0x13)?,
            Some("public-v2.keyx"),
            true,
        ),
        (
            "aes-twofish",
            1,
            OuterCipherConfig::Twofish,
            InnerCipherConfig::Salsa20,
            CompressionConfig::None,
            KdfConfig::Aes { rounds: 10 },
            Some("public.raw"),
            false,
        ),
        (
            "argon2id-aes-hex",
            1,
            OuterCipherConfig::AES256,
            InnerCipherConfig::ChaCha20,
            CompressionConfig::GZip,
            argon(true, 0x13)?,
            Some("public.hex"),
            false,
        ),
    ] {
        let mut config = DatabaseConfig::default();
        config.version = DatabaseVersion::KDB4(minor);
        config.outer_cipher_config = cipher;
        config.inner_cipher_config = inner;
        config.compression_config = compression;
        config.kdf_config = kdf;
        let mut public = VariantDictionary::new();
        public.set("Confidex_PublicFixture", "PUBLIC-EXTENSION".to_owned());
        config.public_custom_data = Some(public);
        let mut database = Database::with_config(config);
        database.root_mut().add_entry().edit(|entry| {
            entry.set_unprotected("Title", "PUBLIC-VECTOR");
            entry.set_unprotected("Unicode", "Почта — 東京");
            entry.set_protected("Password", "PUBLIC-VARIANT-PASSWORD");
            entry.set_protected("Unknown custom", "PUBLIC-VARIANT-CUSTOM");
            entry.add_attachment(
                "résumé.bin",
                Value::protected(b"PUBLIC-KDBX-BINARY\0\xff\n".to_vec()),
            );
            entry.add_attachment("empty.bin", Value::unprotected(Vec::new()));
        });
        let mut key = DatabaseKey::new();
        if password {
            key = key.with_password("PUBLIC-VARIANT-DATABASE");
        }
        if let Some(keyfile) = keyfile {
            key = key.with_keyfile(&mut fs::File::open(output.join(keyfile))?)?;
        }
        database.save(
            &mut fs::File::create(output.join(format!("{name}.kdbx")))?,
            key,
        )?;
    }
    Ok(())
}

# Public KDBX variant fixtures

These files contain synthetic public values only. No accounts, real vaults or
user keys were used. `generate.rs` writes them with the local MIT keepass 0.17.0
library at boundary commit a22c5d067e36fcae7e660ffbaca063b3af7af30b. Fresh random
seeds, IVs and UUIDs make regenerated KDBX bytes differ. The source data and key
bytes are fixed. `manifest.json` pins the captured files and independent reader.

| File | Version | Outer / inner cipher | KDF | Credentials |
| --- | --- | --- | --- | --- |
| argon2d-aes | 4.1 | AES / Salsa20, gzip | Argon2d 0x13 | password |
| argon2id-chacha | 4.1 | ChaCha20 / ChaCha20, gzip | Argon2id 0x13 | password + XML v2 UTF-16 keyfile |
| aes-twofish | 4.1 | Twofish / Salsa20, no compression | AES, 10 rounds | raw 32-byte keyfile |
| argon2id-aes-hex | 4.1 | AES / ChaCha20, gzip | Argon2id 0x13 | 64-character hex keyfile |
| argon2d-aes-v10 | 4.1 | AES / Salsa20, gzip | Argon2d 0x10 | password |

Argon2 fixtures use 64 KiB, two passes, two lanes and 32-byte salts. The database
password is `PUBLIC-VARIANT-DATABASE`. Raw key bytes are byte 9 repeated 32 times;
the hex and XML files encode those same bytes. XML v2 includes its SHA256 prefix.
Each database has a protected password and custom value, Unicode text, a protected
binary with bytes `PUBLIC-KDBX-BINARY` followed by `00 ff 0a`, and an empty file.
It also has a public custom header dictionary item to check exact preservation.

KeePassXC 2.8.0 independently opened the first four files, exported the expected
fields and both exact attachments. Actual XML exports are captured beside them.
Use file attachment export: this CLI's `--stdout` path turns byte ff into the
UTF-8 replacement character. The capture script uses temporary public-fixture
files and compares every byte; it does not hide that difference by decoding text.

The 0x10 variant fails with HMAC mismatch in KeePassXC 2.8.0. The unmodified
registry keepass 0.17.0 reader with rust-argon2 3.0.0 independently opens the same
file and verifies its password value (`upstream.rs`). This is a separate Argon2
implementation and the original model reader, not our raw boundary. Eight fixed
KDF vectors in the library also compare d/id, 0x10/0x13 and one/two lanes.

The [KeePassXC 2.8.0 KDF source](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/crypto/kdf/Argon2Kdf.cpp#L152)
stores a version parameter but does not pass it into its Botan transform. This
source observation is consistent with the runtime difference; it is not a proof
about every KeePassXC build. No compatibility workaround is applied to our reader.

Existing app fixtures separately cover real KeePassXC-produced KDBX 4.0 with AES
and password/raw-keyfile/both. The upstream public database covers KDBX 3.1.
No Cartesian product of every cipher, version, keyfile and KDF profile is claimed.

To verify the captured bytes and independent exports without regeneration:

```sh
python3 vendor/keepass/tests/resources/bounded/capture.py --cli /path/to/keepassxc-cli
```

To reproduce databases, create a disposable Cargo project outside the checkout,
set edition 2021 and add the dependency and binary below, using absolute paths:

```toml
[dependencies]
keepass = { path = "<checkout>/vendor/keepass", features = ["save_kdbx4"] }
[[bin]]
name = "generate"
path = "<checkout>/vendor/keepass/tests/resources/bounded/generate.rs"
```

Run it with this fixture directory as its sole argument. Existing `public.raw`,
`public.hex` and `public-v2.keyx` provide the fixed inputs. Then run capture.py
with `--write` to reopen with KeePassXC and update XML exports and the manifest.
For the separate v1.0 reader check, use another disposable project with
`keepass = "=0.17.0"` from crates.io, binary path `upstream.rs`, and pass the
absolute `argon2d-aes-v10.kdbx` path. Do not patch that dependency to the local
library. No generated source file is sent to any service.

# Password-protected Bitwarden JSON

The adapter opens portable password-protected exports, then calls the existing
Bitwarden JSON mapper. It does not open account-restricted exports or change the
Confidex vault protocol. Unknown wrapper fields and encryption versions require
a supported export; they are never guessed or silently ignored.

The supported wrapper has `encrypted: true`, `passwordProtected: true`, a
canonical Base64 encoding of a 16-byte salt, KDF settings, and two authenticated
EncString values. Only type `2` is accepted: AES-256-CBC with PKCS#7 padding and
HMAC-SHA256 over IV followed by ciphertext. Each MAC is checked before CBC
decryption. The validation plaintext must be a UUID. Both values must open
before any plaintext JSON is mapped. No plaintext file is extracted to disk.

| KDF | Accepted settings |
| --- | --- |
| PBKDF2-HMAC-SHA256, type 0 | 5,000–2,000,000 iterations; memory/parallelism absent or null |
| Argon2id v19, type 1 | 2–10 passes, 16–1024 MiB, 1–16 lanes, subject to the shared memory budget |

These are import admission limits, not recommendations for creating passwords.
The shared 192 MiB memory budget admits the actual Argon2 allocation together
with retained input and decoded data before the library call. It rejects settings
that do not fit, even below the numeric KDF ceiling. Parameters are never reduced.
The input, JSON, decoded payload and record limits also apply.

PBKDF2 uses the UTF-8 salt text. Argon2 uses SHA256 of that same text as its salt
and converts MiB to KiB. HKDF-Expand derives separate 32-byte `enc` and `mac`
keys from the KDF output. Password bytes are used exactly, including Unicode and
spaces. RustCrypto implements all cryptographic operations. Argon2 work memory,
derived keys and plaintext buffers use zeroizing owners. The parser borrows the
host's password; the host must drop its Options after opening and discard work
on cancellation, close, lock or vault switch. These guards do not promise to
clear copies made by JavaScript, the OS or a compiler.

KDF calls run in the host's worker, with cancellation checks immediately before
and after the bounded library call. They cannot be interrupted inside that call.
The native UI thread and browser main thread must not execute this parser.

| Error | Meaning for this adapter |
| --- | --- |
| InvalidOptions | Missing password or invalid shared options |
| UnsupportedFormat | Account-restricted export or unsupported plaintext export |
| UnsupportedVersion | Unknown KDF/encryption/wrapper settings |
| Limit | KDF, input, payload, record or memory admission failed |
| Checksum | Wrong password or damaged authenticated data; use one message |
| Malformed / DuplicateKey | Invalid container or authenticated plaintext JSON |
| Canceled | Work discarded at a checkpoint |

The plan keeps nonsecret KDF settings in `bitwarden.encryption` container
attributes. It does not keep the export password, derived key, salt, validation
token or redundant ciphertext. Plaintext source semantics and private fallback
follow the common JSON mapper. The [encrypted writer](../../export_fixtures/bitwarden_encrypted/COVERAGE.md)
uses fresh salt/IVs and current records. Encrypted import does not imply lossless
reverse export.

## Independent producer evidence

All values and the export password in these fixtures are public test data.
Six valid exports were created by the actual `buildPasswordExport` method and
actual key-generation, encryption, EncString, symmetric-key and WebCrypto
services at clients commit `ae7567e4cc9d8178bf903b060a8c31c10e779509`.
They use the actual `@bitwarden/sdk-internal` 0.2.0-main.1214 WASM crypto, whose
VERSION is `5b7fbb413cf0eff108b0abdbc22607945cc36d8b`.
Only platform utilities and the KDF configuration provider are supplied locally.
The KDF, HKDF, AES and authentication implementation are not mocked.
This is a producer-code/SDK capture, not an installed Bitwarden CLI or UI run.

The Rust fixture tests compare canonical records, source attributes, statuses and
diagnostics against the independent plaintext JSON path for every KDF profile.
They cover incorrect passwords, Unicode/space preservation, changes to each
authenticated component, unsupported settings, bounds, cancellation and memory
release. Authentication does not bypass plaintext JSON validation.

The shared store proof runs against SQLite and the application's actual
BrowserStore/IndexedDB. It checks no writes before confirmation, exact decrypted
records after signing, protected search, reopen and duplicate skip. The browser
probe runs in a real Chrome Worker, checks main-thread heartbeat, blocks external
fetches and enforces 256 MiB WASM memory. Run it from this directory with:

```sh
node ../../import_bitwarden_encrypted/browser.mjs /path/to/chrome
```

Use `CONFIDEX_TEST_CARGO`, `CONFIDEX_TEST_BINDGEN` and `CARGO_TARGET_DIR` for local
tool locations when necessary. This probe exercises the backend and store.

## Application password step

In an open vault, choose **Settings → the vault → Import records** and select
the password-protected JSON export. The application retains the encrypted source
in its service while it asks for the export password. An authentication error
keeps that source for another attempt without selecting the file again. The
password uses its exact UTF-8 bytes; spaces and Unicode normalization are not
changed. A successful open releases the source and password before review.
Close, cancel, lock and destination changes invalidate the pending source or
review. Account-restricted exports return an unsupported-export message without
asking for a password.

The production application check covers the 128 MiB Argon2 fixture at desktop,
intermediate and phone widths. It checks masked password entry, incorrect-password
retry, Enter submission, zero object writes before Apply, three committed records,
credential cancellation and account-restricted rejection. It also saves actual
screenshots. From the repository root, build the browser application and generate
its web bundle with the matching wasm-bindgen CLI, then run:

```sh
node apps/confidex/web/import-ui-check.mjs "$CHROME" "$BUNDLE" "$ARTIFACTS"
```

The native service tests cover password retry, token isolation and cancel/lock
boundaries. Browser checks do not certify native OS windows, physical
phones, every browser or physical memory erasure. Cancellation of a synchronous
KDF takes effect after that bounded library call returns, before storage writes.

## Capture reproduction

The plaintext is the sibling `bitwarden_json/personal.json`, which has separate
schema-derived golden records. The two additional exports deliberately encrypt
invalid JSON or another encrypted wrapper to check authenticated-payload
validation. Source and fixture SHA-256 digests and the SDK package integrity are
in `capture-sources.json`. The generator never reads an account or stored vault.

Fetch the listed source files by basename from the pinned commit of
<https://github.com/bitwarden/clients>. Install the pinned tools outside this
repository, then run:

```sh
npm install --prefix /tmp/bitwarden-capture --save-exact --ignore-scripts --no-audit --no-fund @bitwarden/sdk-internal@0.2.0-main.1214 typescript@5.9.3
node capture.cjs SOURCE_DIRECTORY /tmp/bitwarden-capture/node_modules/@bitwarden/sdk-internal
```

The check verifies source digests and decrypts every capture with the actual SDK.
`--write` regenerates captures and their digests with new random salts, IVs and
validation UUIDs. The harness removes
imports and performance decorators and transpiles TypeScript. Crypto methods and
the exporter execute unchanged.

Primary references:

- [Encrypted export variants](https://bitwarden.com/help/encrypted-export/)
- [Pinned exporter](https://github.com/bitwarden/clients/blob/ae7567e4cc9d8178bf903b060a8c31c10e779509/libs/tools/export-vault-core/src/services/base-vault-export.service.ts)
- [Pinned key derivation](https://github.com/bitwarden/clients/blob/ae7567e4cc9d8178bf903b060a8c31c10e779509/libs/legacy-crypto/src/services/default-key-generation.service.ts)
- [Pinned SDK KDF implementation](https://github.com/bitwarden/sdk-internal/blob/5b7fbb413cf0eff108b0abdbc22607945cc36d8b/crates/bitwarden-crypto/src/keys/kdf.rs)

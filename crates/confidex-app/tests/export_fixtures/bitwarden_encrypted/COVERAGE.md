# Portable password-protected Bitwarden JSON writer

`bitwarden_encrypted_json::Writer::new(profile, options)` wraps the existing
Bitwarden JSON writer. `profile` is `Personal` or `Organization`.
`options` must contain a nonempty password and no keyfile. Passwords use their
exact UTF-8 bytes, up to the shared 65,536-byte limit. Whitespace and Unicode
normalization are not changed. Account-restricted exports are not created.

## Output profile

The wrapper has `encrypted: true`, `passwordProtected: true`, a fresh 16-byte
salt encoded as Base64, and two authenticated type-2 EncString values.
The fixed KDF is Argon2id v19, 64 MiB, three passes and four lanes. The existing
import KDF derives keys from SHA256 of the UTF-8 Base64 salt text, then uses
HKDF-Expand with separate `enc` and `mac` labels. This does not add another KDF
implementation or change accepted import profiles.

RustCrypto AES-256-CBC and PKCS#7 encrypt each stream. HMAC-SHA256 authenticates
its IV followed by ciphertext. The validation value is a new random UUIDv4;
the validation and data streams each have a new random 16-byte IV. A CSPRNG
error returns no artifact. There is no weak fallback or reuse of imported
salts, IVs, passwords, keys or ciphertext.

## Records and losses

Review and JSON serialization use `bitwarden_json::Writer` for the same profile.
Encryption does not remove representation losses or change their consent gate.
The current Record supplies values. Old passwords and deleted identity slots in
source context are not restored. Personal folders use the first tag;
Organization collections use all tags. Access permissions and Confidex revision
history are not exported. Attachments remain a reported loss in this JSON
format; this wrapper does not turn them into embedded data or ZIP members.
See the sibling plaintext writer coverage for its supported field mapping.

## Resources and cleanup

JSON streams through a cleared 16 KiB pending buffer, CBC, HMAC and Base64 into
the shared bounded Output. The writer does not retain a complete plaintext JSON
document or write one to disk. Credentials, scratch work, the Argon2 allocation
and output share the existing memory admission. Default output is at most
64 MiB and the default shared memory limit is 192 MiB. These are ceilings,
not a guarantee that every combination of maximum-sized inputs fits.

Cancellation is checked before and after the bounded KDF and while writing.
Argon2 remains one noninterruptible library call. Close or lock may acknowledge
cancellation while it finishes; the host must discard its result before
publication. Failed, canceled or incomplete outputs are never artifacts.
Owned keys, cipher state and plaintext scratch use zeroizing implementations.
This does not promise physical erasure of compiler, JavaScript or OS copies.

## Independent checks

The reader in `reader.cjs` reuses the existing capture harness and verifies its
source hashes. Key derivation and decryption use actual Bitwarden crypto
services and `@bitwarden/sdk-internal` 0.2.0-main.1214, SDK commit
`5b7fbb413cf0eff108b0abdbc22607945cc36d8b`. The client crypto sources are pinned at
`ae7567e4cc9d8178bf903b060a8c31c10e779509`. Decrypted JSON then passes the actual
JSON importer pinned by the sibling plaintext `reader-sources.json` at
`2ff80e50951792379f970f65cd4fb585fc50bbd5`. No KDF, AES, MAC or importer method
is replaced by a test implementation. Platform utilities and configuration
providers are supplied by the harness. This is source/SDK evidence, not an
installed Bitwarden GUI or CLI import.

The public corpus covers both profiles, edited and removed source values,
Unicode and CRLF, repeated and empty custom names, hidden values, multiple URLs,
card and identity slots, and TOTP. The independent reader rejects wrong,
trimmed and normalized passwords and changes to IV, ciphertext and MAC in both
EncStrings. Native and WASI tests also check shared loss/block gates, memory
admission, output bounds, cancellation and full charge release. A direct cipher
check compares streamed output with the library's one-shot operation at block
and 16 KiB boundaries, including empty plaintext.

Run the independent native check with the three existing source/tool locations:

```sh
CONFIDEX_BITWARDEN_CRYPTO_SOURCE="$CRYPTO_SOURCES" \
CONFIDEX_BITWARDEN_SDK="$SDK_PACKAGE" \
CONFIDEX_BITWARDEN_SOURCE="$JSON_SOURCES" \
cargo test -p confidex-app --release --test export_bitwarden_encrypted -- --include-ignored
```

Build the browser client with `export-check`, produce its web bundle with the
matching wasm-bindgen CLI, then run:

```sh
node apps/confidex/web/export-bitwarden-encrypted-check.mjs "$CHROME" "$BUNDLE" "$PUBLIC_OUTPUT"
node crates/confidex-app/tests/export_fixtures/bitwarden_encrypted/reader.cjs \
  "$CRYPTO_SOURCES" "$SDK_PACKAGE" "$JSON_SOURCES" "$PUBLIC_OUTPUT"
```

The real Chrome Worker checks main-thread heartbeat, the 256 MiB WASM ceiling,
each of four entropy failure points, memory release and successful retry.
External fetches are denied in that worker. Its files are generated from public
test data and can be read independently with the command above.

The real Engine also runs against native SQLite and BrowserStore. It exports
only the current authenticated revision, requires loss consent, and leaves the
source snapshot unchanged. Checks cover post-KDF cancellation, finishing or
canceling a ready artifact, and lock at review and ready stages. Normal builds
prepare both profiles through the serialized production registry. Synthetic
builds retain the direct writer check.

The shared export window offers this format in the normal catalog. Profile and
password travel together in typed options; plaintext JSON rejects these password
options. The window rejects blank or oversized passwords, clears the password
input after preparing the review, and requires new credentials and consent after a
restart. It reuses the existing localized format name in all language catalogs.

Build a browser bundle with `export-ui-check` to keep the production registry.
With the same three source/tool environment variables above, run:

```sh
node apps/confidex/web/export-ui-check.mjs \
  "$CHROME" "$BUNDLE" "$PUBLIC_UI_OUTPUT" en-US bitwarden-encrypted
```

The Chrome UI harness checks both profiles at desktop and narrow widths,
explicit save, fresh consent, save failure, ready cancellation, and lock. The
downloaded encrypted bytes pass the pinned Bitwarden crypto services, SDK, and
JSON importer. The UI corpus has current Unicode and multiline passwords,
empty/repeated custom names, hidden values, and folder/collection relationships.
Trimmed passwords fail decryption. New exports must use different salts.

These checks do not certify the native OS picker, Safari, Firefox, a physical
phone or a 10,000-record workload. Diagnostic exports alone do not certify the
production window.

Primary references:

- [Pinned password export builder](https://github.com/bitwarden/clients/blob/ae7567e4cc9d8178bf903b060a8c31c10e779509/libs/tools/export-vault-core/src/services/base-vault-export.service.ts)
- [Pinned key generation](https://github.com/bitwarden/clients/blob/ae7567e4cc9d8178bf903b060a8c31c10e779509/libs/legacy-crypto/src/services/default-key-generation.service.ts)
- [Pinned SDK KDF](https://github.com/bitwarden/sdk-internal/blob/5b7fbb413cf0eff108b0abdbc22607945cc36d8b/crates/bitwarden-crypto/src/keys/kdf.rs)

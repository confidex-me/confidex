# Local keepass integration

This is the MIT-licensed `keepass` 0.17.0 published crate. `UPSTREAM.json` pins the
crate checksum, the publisher's VCS metadata and every original file hash. The
publisher marked its VCS tree dirty; the exact archive checksum, rather than
that commit alone, identifies these sources. The original MIT license and
copyright remain in `LICENSE`.

`bounded::Raw::open` provides the application's raw KDBX decoding boundary.
Independent variant coverage is recorded in `tests/resources/bounded/CAPTURE.md`;
The application uses its own bounded XML and field mapping.
Existing `Database::open`, `parse` and `get_xml` do not
provide that policy and must not be used as the import boundary.

The application disables optional save, utility and hardware features for import:

```toml
keepass = { path = "../../vendor/keepass", default-features = false }
```

The app adapter must pass its remaining shared memory allowance,
reserve Raw/Protected together with decoded and mapped outputs, and use its own
bounded XML/base64 mapper. Read binary pool entries by their original index.
The boundary never sends input to the sync server or mutates a vault.

Current changes from the published archive:

- `Cargo.toml`: a separate workspace for isolated library checks, inclusion of
  the missing upstream test file, and removal of unused dev dependencies for
  integration tests that are absent from the published crate. RustCrypto
  `argon2 =0.6.0` replaces `rust-argon2`; AES, SHA2 and hybrid-array enable
  their zeroize features. This matches the backend used by Confidex core.
- `Cargo.lock`: re-resolved after removing those dev dependencies.
- `src/lib.rs`: registers the internal bounded helper.
- `src/compression.rs`: reuses bounded gzip code. The legacy method passes
  unlimited output/memory values; this is not the safe importer entry point.
- `src/bounded/mod.rs`: bounded output and vector-growth peak, a conservative
  decoder scratch admission, zeroizing buffers, per-chunk cancellation, bounded
  optional gzip headers before decoder creation, checksum/EOF validation and
  rejection of concatenated members or trailing bytes.
- `src/db/mod.rs`: embeds the original public test database instead of opening
  a relative filesystem path. The published crate omitted that file. Its exact
  upstream source and hash are recorded separately in `UPSTREAM.json`.
- `src/format/variant_dictionary.rs`: checks scalar sizes before byte reads,
  strict UTF-8, unique keys, exact termination, and caps input at 1 MiB,
  256 entries and 4096 bytes per key. This closes malformed KDF/custom-data
  parsing paths used by the existing KDBX4 reader; it does not bound that reader.
- `src/bounded/limits.rs`, `src/crypt/kdf.rs`: KDF admission checks memory,
  passes, lanes, work product and AES rounds before work. Caller limits can
  only reduce the defaults. AES checks cancellation every 1024 rounds;
  Argon2 checks before and after the library call. Argon2 working blocks and
  intermediate AES blocks use zeroizing buffers with fallible allocation.
  `config.rs` and KDBX4 tests use the RustCrypto version/algorithm enum names.
  Existing KDF callers now also receive the default limits.
- `src/bounded/header.rs`: `Header::inspect` admits versions 3.1/4.0/4.1,
  required fields, fixed sizes, unique tags, supported KDF keys, public header
  SHA256 and complete block framing before KDF work. It borrows the original
  header and encrypted stream. It does not authenticate either; its name and
  documentation do not imply authenticated data.
- `src/crypt/ciphers.rs`: fallible zeroizing decryption buffers clear on errors,
  CBC key/IV copies clear on drop, and stream ciphers report exhaustion instead
  of panicking. Twofish now truncates the returned PKCS7 padding, as AES does.
  CBC, Twofish, ChaCha20, Salsa20 and HMAC also enable zeroize features.
  Successful legacy decrypt calls still return a normal Vec; the raw entry
  point wraps it immediately and accounts for its memory.
  Optional encryption uses the same fallible zeroizing buffers; CBC padded sizes
  reject integer overflow, and stream encryption uses the existing checked
  keystream path.
- `src/key/mod.rs`, `src/key/xml.rs`: cap keyfile reads at 1 MiB; clear read,
  composite-element and XML text buffers; redact DatabaseKey Debug output.
  Parse XML v1 base64 and v2 hex keys as exactly 32 bytes, verify v2's four-byte
  SHA256 prefix, reject duplicates/unknown versions/DTD/entities in recognized
  KeyFile documents, and support UTF-8 plus BOM-marked UTF-16 LE/BE. Raw 32-byte,
  64-character hex and other bare files retain the existing key interpretation.
  Malformed recognized XML keys now fail instead of silently becoming bare keys.
  See the [KeePass keyfile documentation](https://keepass.info/help/base/keys.html).
- `src/bounded/raw.rs`: admit buffers before work, authenticate the KDBX4
  header and complete encrypted stream with constant-time library HMAC
  verification, then decrypt/decompress into zeroizing buffers. KDBX3.1 checks
  start bytes, sequential hashed blocks and mandatory Meta/HeaderHash binding.
  It retains the exact XML, outer header and KDBX4 binary pool, without a DOM.
  `take_protected` transfers one owned inner stream so callers can borrow the
  XML and consume every protected node, including unknown/history values, in
  physical order. Library `subtle` supplies the KDBX3 start-byte comparison.
- `src/format/kdbx4/dump.rs`: writes the specified four-byte CR/LF outer END
  value instead of an empty value. This lets the fixture writer produce a
  header accepted by the strict reader; the inner END value remains empty.
  HMAC framing writes directly to the destination without another complete
  framed ciphertext buffer. The shared HMAC writer uses sequential 64 KiB
  blocks and a final authenticated empty block, and propagates I/O failures.

The optional `bounded::save` bridge uses the same prepared keys, header, ciphers
and HMAC writer as the legacy save path. The caller supplies current XML through
a checked `Write` sink and borrowed binary entries. `Encoder` consumes protected
values in physical XML order. It does not build the legacy database model or
interpret XML, groups, keys or references; the application owns those semantics.

The bridge accepts KDBX4.1, AES256, ChaCha20 inner protection and no compression.
Gzip compressor history has no zeroization contract, so the bridge rejects it
before work. This does not change compressed input support or the legacy writer.
Password/keyfile presence is explicit, including an empty password. Passwords
are capped at 4096 bytes and keyfiles at 1 MiB. The existing key parser and KDF
admission apply. Library buffers clear on exit, vector growth charges both old
and new allocations, and memory events report a total live work charge before
allocation and after release. The caller must include this charge in its shared
budget, along with borrowed inputs, XML formatting buffers and its destination.
An 8 MiB allowance covers header, key parsing and small cipher state; Argon2 adds
its declared work memory plus 1 MiB. These are conservative admission counts,
not allocator measurements. Callbacks can stop KDF, XML and final output work;
Argon2 remains one synchronous call. No output is written before payload sealing
and size admission. An I/O failure can leave partial ciphertext in the caller's
destination, which must be discarded and never published. `SaveError` contains
no values. Fresh randomness errors fail instead of using a fallback.

The legacy database-model save API still does not bound its XML serialization
or compression. It is not the application's export boundary.

Raw defaults: file/output 64 MiB, header 1 MiB, 16,384 blocks/pool entries,
192 MiB decoder working memory. Borrowed inputs and caller-retained outputs
are excluded. A conservative 8 MiB allowance covers metadata, key parsing and
small cipher state. Payload admission covers two file-sized buffers; inflate
also counts compressed input, output growth and decoder scratch. `memory_bytes`
reports retained vector capacities plus a cipher allowance. Callers must keep
their own shared reservation while Raw/Protected and mapped results coexist.
It is not an allocator measurement or a whole-app heap guarantee.

KDBX3.1 has encrypted hashes, not the KDBX4 HMAC authentication scheme. The raw
boundary does not upgrade the source format's security. KDBX3 HeaderHash scanning
caps XML depth at 64 and events at 1,000,000 and rejects DTD. KDBX4 XML semantics,
node/string bounds and preserving unsupported application data remain the
import mapper's responsibility. No source URL or external resource is opened.

KDF defaults: AES 25,000,000 rounds; Argon2 64 MiB, 1024 passes, 16 lanes,
and 16 GiB of memory multiplied by passes (256 passes at 64 MiB). These are
resource ceilings, not a promise that the maximum profile is responsive in a browser. Argon2
cannot stop during its synchronous library call. Eight public vectors from
`rust-argon2 =3.0.0` check d/id, versions 0x10/0x13 and one/two lanes against
the new backend (input byte 7 repeated 32 times, salt byte 9 repeated 32 times,
64 KiB, two passes, 32-byte output).

`python3 verify_upstream.py` checks that no other upstream source changed and
that the added upstream fixture is exact. It does not approve the local patch;
review the patch and run its tests separately.

From the repository root, with an external target directory:

```
CARGO_TARGET_DIR=/tmp/confidex-kdbx-boundary-target cargo test --manifest-path vendor/keepass/Cargo.toml --lib
```

The four bounded test groups also run on wasm32-wasip1 with the project's Node
WASI runner. The three real KDBX capture profiles still open through the patched
legacy parser; that only proves gzip interoperability, not a safe import flow.
Strict library Clippy currently reports existing upstream duplicate dependency,
Default-implementation and ID-constructor warnings. They are not suppressed or
presented as a passing check.

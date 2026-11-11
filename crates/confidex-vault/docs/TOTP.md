# TOTP values

`totp/v1` stores `secret: bin` (1–128 bytes) and optional `algorithm: str`
(`SHA1`, `SHA256`, `SHA512`, default `SHA1`), `digits: uint` (6–8, default 6),
`period: uint` (1–86,400 seconds, default 30), and `t0: uint` (default 0).
Unknown fields remain intact. All parameters stay inside encrypted content.
`Entry::validate_value` and `totp::Totp::from_value` explicitly check these types
and ranges. Ordinary Record reading preserves even invalid parameters.

`Totp::new` borrows a decoded secret with explicit parameters. `generate(time)`
implements [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238.txt) using RustCrypto
HMAC and SHA-1/256/512. Pass Unix **seconds**, independently of metadata epoch
milliseconds. No system clock, network, or entropy is read. Time before `t0`
returns an error; counters support the full u64 range. Code exposes zero-padded
digits through `as_str()` and the seconds remaining in the current step through
`valid_for_seconds` (a full period at the step boundary).

`verify(time, candidate)` compares the current code with `subtle::ConstantTimeEq`;
length is public. No window search, replay prevention, or rate limiting is
implicit. The application supplies clock/skew and authentication policies.
HMAC uses the dependencies' zeroization features; returned codes and owned
digest buffers clear on drop. No constant-time guarantee is made for decimal
formatting or arbitrary parameter parsing, nor for removal of compiler copies.

`decode_secret` imports RFC 4648 Base32, ASCII case-insensitively, with canonical
padding or none. It rejects separators, whitespace, incorrect padding, nonzero
unused bits, empty secrets, and input over 208 bytes before allocating. Its
fallibly allocated output is zeroizing. This encoding is independent of the
fixed-length, grouped vault transfer-code format. URI/QR provisioning belongs to
the application. Provisioning must supply a strong secret; accepting a short
legacy secret does not make it strong. Keeping TOTP and a password in the same
vault lets compromise of an unlocked vault disclose both authentication factors.

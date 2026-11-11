# Raw secret-key text codec (construction fixtures)

This documents `secret_key_text`, the low-level 32-byte codec retained for
construction tests and vectors. It is not the current application's input or
display format. Clients use the [transfer code](../TRANSFER-CODE.md):
48 bytes, 77 Base32 symbols in 11 groups of seven, including the public sync UUID
and a four-bit checksum. Client create/unlock/import paths do not fall back to
the raw codec. The rules below describe only that separate utility.

Encode the 32 raw bytes of the hidden X25519 public key as standard RFC 4648
Base32 (`A–Z`, `2–7`), without `=` padding. It has 52 data characters. Canonical
display uses groups of 6,7,6,7,6,7,6,7 with seven ASCII hyphens: 59 characters.
This is not Crockford Base32.

Accept exactly that grouping or exactly 52 ungrouped characters. Ignore ASCII
letter case and remove only outer whitespace bytes `09–0d` and `20`. Reject
internal whitespace, misplaced/extra/missing separators, Unicode lookalikes,
`=`, prefixes/suffixes, and non-alphabet digits. Do not map `0` to `O` or `1` to
`I`/`L`. Bound received text to 128 bytes before normalization. Output is uppercase
and grouped, with no outer whitespace.

The final symbol has one data bit and four zero pad bits: it must be `A` or `Q`
after case normalization. Reject all other final values instead of erasing their
nonzero unused bits. Decode exactly 32 bytes. See
[RFC 4648 sections 3.5 and 6](https://www.rfc-editor.org/rfc/rfc4648.html).

The raw codec adds no checksum or text version prefix. Its 52 characters encode
only key bytes. The current transfer-code codec is selected explicitly at the
application boundary, not guessed after a raw-codec parse failure.
Syntax checks do not detect every typo: a valid alphabet substitution may yield
a different key. Successful decoding does not prove vault membership. Lock
authentication and the recovered material/key correspondence check do that.

Pass decoded bytes to the lock KDF, never display spelling or separators. This
codec checks syntax, not X25519 correspondence/entropy. It round-trips any 32
bytes; the vault operations apply cryptographic checks separately. The encoded
public key remains a secret access factor. Keep it out of server requests,
logs, and open metadata.

The codec uses fixed-size `Zeroizing` outputs without heap allocation. The
caller controls the lifetime of its input text and any display copies. No
constant-time claim is made for this presentation codec. Errors contain no
input text.

Tests cover a standard-library reference fixture, every input bit, all 30 invalid
pad-bit variants, allowed normalization and identical KDF bytes, malformed text,
the input cap, and a valid-character typo that changes the decoded key.

# Pinned producer capture

`producer-personal.json` is output from Bitwarden's actual individual JSON
exporter and export models at clients commit
`2ff80e50951792379f970f65cd4fb585fc50bbd5`. This is a serializer capture with
mocked decrypted data providers, not an installed CLI or UI export. It does not
prove that the producer accepts each input through its editor or server.

All inputs in `producer-input.json` are public synthetic data. The SSH key and
passkey are deliberately invalid marker strings: they test retention and error
reporting, not working credential migration. Item types 6/7/8 test protected
fallback for newer categories. Deleted, organizational and restricted items are
present only in the input and must be excluded from the personal output.

`capture-sources.json` lists the upstream paths and SHA-256 digests in evaluation
order. Fetch each file from the pinned commit of
<https://github.com/bitwarden/clients> into one directory using its basename.
Then run with Node 26.10.0:

```sh
node capture.cjs /path/to/upstream-source-directory
```

The check verifies every source digest, executes the exporter, checks field
ordering, hidden/linked/unknown flags, filtering, cipher-key redaction and passkey
string serialization, and compares the output byte for byte. Add `--write` only
to regenerate the checked-in capture. No account, network request, application
dependency or production cryptographic service is used during this check.

The harness removes imports and the unused service constructor before Node's
TypeScript stripping. Providers, observable resolution, crypto guards, the base
service, domain identity checks, two default enums and the passkey view class are
mocked. Export methods and field serializers execute unchanged. The shared
golden manifest and expected-record matrix remain separate; adapter tests must
check the mapping independently of this producer check.

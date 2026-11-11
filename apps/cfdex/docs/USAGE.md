# cfdex

`cfdex` reads local Confidex vaults on macOS, Linux, and Windows. It shares
the native app's database and device key. The CLI starts its own agent and
requires a separate unlock. `cfdex lock` clears the selected CLI session.

## Build and install

Use a current Rust toolchain and the platform's C toolchain for bundled SQLite.
On Linux, the build also needs `pkg-config` and the TPM2-TSS development
libraries (`libtss2-dev` on Ubuntu). The Linux executable needs the corresponding
runtime libraries.

```sh
cargo build --locked --release -p cfdex
cargo install --locked --path apps/cfdex
```

The build produces `target/release/cfdex` or `target/release/cfdex.exe`.
For a build with folder sync and no HTTP transport, add `--no-default-features`.
`cfdex --help` and `cfdex --version` work before setup.

## First run

Run `cfdex init` to select a local vault, create one, or connect to a server.
Selection and creation work offline. Use `--database PATH` to work with a
separate database. Omit it to use the native app's database.

```sh
cfdex init --select 'Example vault'
cfdex unlock
cfdex list --tag Login --json
cfdex fields 'Example account'
cfdex get 'Example account' --field Password
cfdex sync
cfdex lock
```

## Commands

| Command | Result |
| --- | --- |
| `init` | Select or set up a vault and save its stable ID as the CLI default. |
| `vaults` | List local vault IDs and names without unlocking them. |
| `status` | Show whether the selected vault is locked or unlocked in the CLI. |
| `unlock` | Open the vault with its password and saved or explicitly entered key. |
| `lock` | Clear the selected CLI session. The GUI remains unchanged. |
| `list [QUERY]` | List or search local records, with optional `--tag TAG`. |
| `fields RECORD` | List field indices, names, types, and value-key names, without values. |
| `get RECORD --field NAME` | Return one uniquely named field value. |
| `get RECORD --field-index N` | Select a field by its zero-based position. |
| `sync` | Explicitly synchronize the selected unlocked vault. |

Global options are `--vault ID_OR_NAME`, `--database PATH`, `--json`, `--help`,
and `--version`. A saved default is a stable VaultId, not a display name. CLI
preferences must not change the GUI's current vault or draft. There are no
`cdx` or `cdex` aliases.

Records accept a stable RecordId or an exact unique title. Duplicate vault or
record names fail with safe candidate IDs. `--field NAME` requires exactly one
matching field; empty or duplicate field names use `--field-index`. A structured
field with several value keys also requires `--value KEY`. Names are user data
and are not translated. A record with several heads requires an explicit
`--revision ID`; the CLI never silently picks or merges a branch.

`get` emits only the selected value. Binary data requires `--output PATH`; the
file is created exclusively with private permissions. Existing files are not
overwritten. Unknown field types remain readable where their value is supported;
unsupported encodings fail without rewriting the record. Local reads do not
start a sync or fetch URLs found in records. List/search must traverse all pages
and finish application indexing before reporting the final result. If the
complete result exceeds the metadata limit, narrow the query or filter by tag.

For an attachment, inspect its keys with `fields`, then select its binary value.

```sh
cfdex get 'Example license' --field License --value data --output ./license.bin
```

Sync follows the vault's existing settings. With both transports configured,
it synchronizes the folder, completes HTTP sync, then synchronizes the folder
again. Resolve conflicting revisions in the Confidex app. The CLI can read
either branch by its revision ID. An interrupted sync can resume from the
last saved checkpoint.

## Credentials and process behavior

TTY input hides the password and secret key. The CLI client reads the same
hardware-protected device key as the GUI. If the saved key is unavailable,
interactive unlock requests the key separately. Noninteractive unlock requires
it in the explicit JSON input in that case. Unlock always requires the password.

Noninteractive commands do not prompt. An explicit `--credentials-stdin` on
`unlock` or credential-requiring `init` actions accepts one bounded JSON object
with `password` and optional `secret_key`. Credentials are never accepted as
argument or environment-variable values. Read commands do not consume stdin to
obtain credentials. No credentials, session keys, or record dumps are written to
logs or automatic temporary files.

Creating a vault must save a separate key backup to an explicit private output
file and remember its key through the existing device-key policy. Failure to
save that backup must not be reported as a completed setup. Server access is
never required for local creation. Connecting a remote vault is an explicitly
selected network operation. Repeated or cancelled init preserves other vaults,
credentials, records, and unfinished work.

Without a TTY, init requires an explicit action: `--select ID_OR_NAME`,
`--create NAME`, or `--connect NAME`. Create requires `--key-output PATH`;
connect accepts `--server URL`. Credential-requiring actions also require
`--credentials-stdin` without a TTY. Only one action is permitted. Interactive
init asks for the action and missing inputs; cancellation preserves the previous
default. Selecting a local vault does not require unlocking it.

The agent is a private mode of the same executable, started on demand.
It owns vault-scoped engines and serializes operations. The idle timeout
is 15 minutes per vault; explicit lock, timeout and agent exit drop keys and
plaintext caches. Restart never restores an unlocked session. Lock completion
must not be followed by disclosure from an older in-flight request. Concurrent
startup and crash recovery must not remove another live process's endpoint.
The agent serializes requests: lock acknowledgement follows earlier completed
responses. Bytes already given to another process cannot be recalled. Status
polling does not renew the idle deadline. Up to 16 vault sessions can be open;
lock a vault before opening another when this limit is reached.

| State | Allowed behavior |
| --- | --- |
| No default vault | `vaults`, explicit `--vault`, and `init` remain available. Other commands fail with a selection error. |
| Agent absent | A session command starts or connects to the agent; it does not launch the GUI. |
| Vault locked | `status`, `init`, `vaults`, and idempotent `lock` work. `unlock` can request credentials on a TTY. Reads and sync fail with an unlock instruction. |
| Vault unlocked | Local read commands work offline. `sync` uses existing configuration and the optional transport. |
| Invalid credentials | Unlock fails; the database, saved key and other vault sessions remain unchanged. |
| Idle timeout or agent crash | The next read reports locked; no saved password is used to unlock automatically. |

## Output and failures

Help and diagnostics are English. User titles, tags and field names retain their
original language. Stdout contains only the result, stderr contains diagnostics
and progress. Redirected output has no ANSI sequences. Text `get` writes the
exact UTF-8 value without adding a newline; `--json` uses JSON string escaping.

JSON responses use an envelope with `version: 1` and `result`; failures use
`version: 1` and `error` with a stable `code` and safe `message`. JSON errors go
to stderr. Metadata responses exclude field values. JSON is not a raw dump of
the internal `Output` or `Draft` types.

| Exit code | Meaning |
| --- | --- |
| 0 | Success. |
| 1 | I/O, storage, or internal failure. |
| 2 | Invalid arguments or input. |
| 3 | Vault is locked or credentials are unavailable. |
| 4 | Selection not found. |
| 5 | Ambiguous selection or conflicting revisions. |
| 6 | Authentication failed or access was denied. |
| 7 | Network or synchronization failure. |
| 8 | Incompatible, invalid, or unavailable agent protocol. |
| 130 | Cancelled by the user. |

## Boundaries and verification

`crates/confidex-native` owns shared database opening, device credentials, and
the optional native transport. It has no GUI dependency. `apps/confidex` retains
GUI dispatch and browser adapters. The `apps/cfdex` modules separate argument
parsing/output, credential input, bounded IPC framing/peer checks, agent
lifecycle, and the operation dispatcher. Application commands, wire objects,
revision graphs, storage schema and cryptography remain in their existing crates.

IPC is local: private Unix sockets with directory ownership, permissions and
peer checks, or Windows named pipes with suitable ACLs and client checks. Version,
request ID, vault scope, operation and finite frame limits are mandatory. Only
explicit operations are exposed; there is no generic internal-command RPC. Frames
are validated before allocation or execution. Selected binary payloads need a
bounded transfer without expanding an arbitrary record into JSON. Same-user IPC
does not isolate secrets from a compromised process of the same user.

The implemented version-1 framing uses a four-byte big-endian JSON-header length.
Requests have a 64 KiB limit; response metadata has a 64 MiB limit. Selected text,
binary values, and a newly created key use a separate raw payload of at most
64 MiB. The client validates the version, request ID, vault scope, reply kind,
payload length, and text encoding before exposing a result. Metadata replies
cannot include a raw payload. A malformed or truncated exchange closes the
connection; it must not produce partial output.

Request operations use external JSON tags, such as `{"status":{}}`. Credentials
use bounded UTF-8 byte arrays inside the private protocol so escaped JSON strings
do not create parser scratch copies of passwords. This encoding is not encryption.
It is separate from the user-facing JSON input/output contract. Owned credential
and transfer buffers are cleared on drop, including error paths; OS, terminal,
shell pipeline and framework copies cannot be guaranteed erased.

The Unix transport checks the private directory and socket owner/permissions,
verifies the effective peer UID in both directions, limits connect time, and
uses one deadline across a whole exchange. It preserves a replacement path when
dropping its listener. Windows uses a local named pipe with a user-SID DACL and
checks the peer process's token SID in both directions.
The client reads device credentials before sending an unlock request. The agent
does not open Keychain dialogs. Unix processes disable core files; Linux also
disables process dumping. These controls do not erase OS or framework copies.

Acceptance covers actual separate processes and prepared artifacts, offline
reads, the shared macOS credential, concurrent database writes/CAS, pagination,
duplicate/Unicode/unknown fields, branch selection, TTY and JSON output, bad
credentials, cancellation, agent startup/crash/timeout/lock, malformed frames,
peer rejection and resource bounds. Platform results must identify what was
actually checked. Tests use synthetic data. Run them with
`cargo test --locked --release -p cfdex`. The ignored macOS device-key test
requires an available login Keychain and Secure Enclave. It creates and removes
its own synthetic credential.

CRUD, generators, TOTP, clipboard, CLI import/export, SSH/OpenPGP integration and
moving the GUI into the agent are outside the first delivery. Package registry
registration, public releases and deployment require a separate request.

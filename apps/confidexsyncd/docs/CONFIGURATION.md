# Sync server configuration

`confidexsyncd` serves the [synchronization REST API](SYNC-API.md).
The production hostname is `sync.confidex.me`. GET and HEAD `/` return an empty
404 without redirecting or accessing storage. The daemon does not select an
application hostname.
Production adds an independent Cloudflare Redirect Rule from GET/HEAD
`https://sync.confidex.me/` to `https://app.confidex.me/` (307, query discarded).
The deployment rule is [`cloudflare-root-redirect.json`](../cloudflare-root-redirect.json)
in the zone's `http_request_dynamic_redirect` entrypoint. It matches only that
host, exact root path and those two methods; `/v1` and all API paths are excluded.
Other installations can omit or change the rule without rebuilding syncd.
`/v1` serves Swagger UI, and `/v1/openapi.json` serves its OpenAPI specification.
Swagger UI 5.34.1 assets are embedded and served from the same origin; the
documentation does not use a CDN or an external validator.
The HTTP API permits CORS from any origin, accepts preflight OPTIONS without
storage access, and exposes all response headers. Cross-origin clients omit
cookies; writes still require valid object signatures.
The Cloudflare sync API also skips browser-integrity and security-level checks
that can require a browser clearance cookie. The scoped deployment rule is
[`cloudflare-api-rule.json`](../cloudflare-api-rule.json); apply it to the zone's
`http_request_firewall_custom` entrypoint. It matches only `sync.confidex.me`
and `/v1/sync` or its children, regardless of Origin. It does not skip managed
WAF rules, rate limits or DDoS protection. Other installations must use their
own hostname. Signature verification remains in the Worker.
The native binary and Worker share lock inspection, signature verification,
multipart parsing, graph checks, pagination and transactional index operations.
This service does not implement the application's sync client or conflict UI.
Those live in `confidex-app` and `confidex-ui`. See the [sync architecture and
recovery guide](SYNC.md) for the module map, client/server sequence,
stored data, write publication rules and backup/restore procedure.

The server accepts parallel revisions of one record and returns every branch.
Each parent must already exist or precede its child in the same batch; a parent
does not have to be the latest revision. A stale cursor requires a history pull
and a retry with the missing objects, without a merge or new signatures.
Older clients can still reject multiple heads; server acceptance alone does not
make those clients compatible with branched histories.

## Sharing an origin with the app

An installation can serve the web app and sync API on one domain. Route exact
`/v1` and the `/v1/` prefix (including sync, OpenAPI and Swagger assets) to syncd;
route `/` and the remaining app asset paths to the app host. Give these API
routes priority over a static host's HTML fallback. This routing belongs to the
reverse proxy or hosting platform; syncd does not serve app assets itself.

Set the client's custom sync server URL to that origin, for example
`https://vault.example.org/`; the client adds `/v1/sync`. The browser's
fixed `https://sync.confidex.me/` default does not detect shared-origin
installations. The existing production app and sync domains remain separate.

## Native configuration

Run with a TOML file:

```sh
cargo run --release -p confidexsyncd -- apps/confidexsyncd/example.toml
```

Paths are relative to the process working directory. The example mirrors
objects to a local directory and a local bare Git repository. Git must be on
PATH. The backend stores immutable Git blobs under `refs/confidexsyncd/<hash>`;
it does not create a working tree or automatically push to a remote. Use a
mirror clone or the repository's normal backup tooling to copy those refs.

```toml
[index]
url = "confidexsyncd.sqlite"

[listen]
address = "127.0.0.1"
port = 8080

[limits]
body_bytes = 8000000

[[backend.posix]]
path = "/srv/confidex/objects"

[[backend.git]]
path = "/srv/confidex/objects.git"

[[backend.s3]]
url = "https://s3.example.net/primary?region=us-east-1"
access_key = "replace-with-backend-access-key"
secret_key = "replace-with-backend-secret-key"

[[backend.s3]]
url = "https://s3.example.net/secondary?region=us-east-1"
access_key = "replace-with-other-backend-access-key"
secret_key = "replace-with-other-backend-secret-key"
```

For PostgreSQL, set `index.url` to a PostgreSQL connection URL. TLS parameters
are supported by the driver. For SQLite, use a file path or `sqlite:<path>`;
the daemon enables WAL, FULL synchronization and foreign keys. Tables have the
`sync_` prefix and are created at startup. S3 buckets must already exist.

An S3 URL contains the endpoint and bucket, with optional `?region=...`.
The region defaults to `auto` for R2. Custom endpoint prefixes are supported.
Requests use path-style addressing and AWS Signature Version 4. Backend
credentials authorize storage access; they are unrelated to vault keys.

S3 objects share the server vault UUID as their prefix:

```text
{uuidHex[0..2]}/{uuidHex[2..4]}/{uuid}/{sha256[0..2]}/{sha256[2..4]}/{sha256[4..]}
{uuidHex[0..2]}/{uuidHex[2..4]}/{uuid}/locks/{sha256}.sealed
```

`uuidHex` is the UUID without dashes. These prefixes help browse the bucket;
synchronization uses indexed object keys and does not list S3.

The digest covers the exact encrypted wire bytes. Lock versions are immutable:
the index publishes a replacement only after every mirror has stored it, so
concurrent password changes cannot overwrite the winning lock. POSIX and Git
backends retain their digest-based object names. Existing S3 installations must
copy their indexed objects to this layout before upgrading; there is no fallback
to the former prefixes.

## Environment configuration

With no file argument, the daemon reads the environment. There is one mapping:
uppercase the TOML field path, replace dots with underscores, and put the array
index at the end. The lists have independent indices and may contain gaps.

| TOML field | Environment variable |
| --- | --- |
| `index.url` | `INDEX_URL` |
| `listen.address` | `LISTEN_ADDRESS` |
| `listen.port` | `LISTEN_PORT` |
| `limits.body_bytes` | `LIMITS_BODY_BYTES` |
| `backend.posix[0].path` | `BACKEND_POSIX_PATH_0` |
| `backend.git[0].path` | `BACKEND_GIT_PATH_0` |
| `backend.s3[0].url` | `BACKEND_S3_URL_0` |
| `backend.s3[0].access_key` | `BACKEND_S3_ACCESS_KEY_0` |
| `backend.s3[0].secret_key` | `BACKEND_S3_SECRET_KEY_0` |

Defaults are index `confidexsyncd.sqlite`, address `127.0.0.1`, port `8080`.
At least one complete backend section is required. An incomplete numbered
section fails configuration instead of silently removing that destination.

```sh
INDEX_URL=/srv/confidex/index.sqlite \
LISTEN_ADDRESS=127.0.0.1 LISTEN_PORT=8080 \
BACKEND_POSIX_PATH_0=/srv/confidex/objects \
BACKEND_GIT_PATH_0=/srv/confidex/objects.git \
cargo run --release -p confidexsyncd
```

The binary serves HTTP; a deployment proxy supplies HTTPS. Four requests can
enter the native body/verification path at once. Each input body is buffered
with an enforced 8 MB bound, then parsed. This is bounded buffering, not a claim
of zero-copy streaming. Slow native request bodies have a 30-second deadline.

`limits.body_bytes` maps to `LIMITS_BODY_BYTES` on native and Workers. The
default and ceiling are 8,000,000 bytes, including multipart framing. A smaller
limit rejects uploads with `413` and advertises the limit in
`Sync-Max-Body-Bytes`. Download pages retain their 8 MB limit. The maximum wire
record is 4,065,668 bytes; limits below that size cannot accept all records.

## Cloudflare Workers

The Worker is the library's `cdylib` WASM entrypoint, built from the same package.
The native `main` executable is not used by the Workers runtime.

```sh
npm ci
python3 builders/syncd/build.py
npx wrangler d1 execute confidexsyncd-index --local --config apps/confidexsyncd/wrangler.toml --file apps/confidexsyncd/schema.sql
npx wrangler dev --local --config apps/confidexsyncd/wrangler.toml
```

Run these commands from the repository root. The Python builder pins worker-build
and emits the JavaScript loader and WASM under ignored `apps/confidexsyncd/build/`.
Wrangler uses those compiled files; it does not run a Rust build. The tracked `wrangler.toml`
is a template. Copy it to ignored `wrangler.production.toml`, set the account,
D1 database ID and R2 S3 URL there, and deploy with `--config wrangler.production.toml`.
The configuration disables workers.dev and preview URLs and declares the
`sync.confidex.me` custom domain. Supply
`BACKEND_S3_ACCESS_KEY_n` and `BACKEND_S3_SECRET_KEY_n` through Worker secrets
(or ignored `.dev.vars` for local development). Both numbered URLs and secrets
use the same configuration mapping as native. The Worker accepts S3 backends
only. POSIX and Git are not compiled into it.

The S3 token must grant object read/write access to the `confidexsyncd` bucket.
Keep the token values in Worker secrets. Releasing the browser application on
`app.confidex.me` is separate from deploying this daemon.

D1 schema application and deployment to a real account are separate operations.
Local Wrangler uses its own D1 database, but S3 URLs still refer to the endpoints
you configure. Use disposable endpoints for tests. The Worker uses a D1 session
anchored at the primary for sequentially consistent reads and atomic batch
writes. Large batches can exceed free-tier CPU or query allowances; select an
appropriate Workers plan before running a public service.

## Verification

```sh
cargo test -p confidexsyncd
cargo test -p confidex-vault --test lock
cargo clippy -p confidexsyncd --all-targets -- -D warnings
cargo check -p confidexsyncd --lib --target wasm32-unknown-unknown
```

With a server running, use `node apps/confidexsyncd/check-openapi.mjs
/path/to/chrome http://127.0.0.1:8080` from the repository root to check that
Swagger UI renders all six operations and loads resources from that origin only.

The normal tests cover lock replacement and replay rejection, signed history
and deletions, invalid batches, independent SQLite connections racing a CAS,
FS/Git mirrors, corrupt-copy fallback, failed writes without index publication,
and actual HTTP uploads exceeding the body limit without Content-Length.

Ignored integration tests use disposable external services:

```sh
CONFIDEX_TEST_POSTGRES=postgres://user:password@127.0.0.1:5432/test \
CONFIDEX_TEST_S3=http://127.0.0.1:9000 \
cargo test -p confidexsyncd --test api postgres_with_s3_and_fs -- --ignored

CONFIDEX_TEST_WORKER=http://127.0.0.1:8787 \
cargo test -p confidexsyncd --test api worker_full_lifecycle -- --ignored
```

The PostgreSQL/S3 test needs a fresh database and S3 credentials
`sync-test-key` / `sync-test-secret`; it creates two test buckets. The Worker
test needs a fresh local D1 index and those existing buckets configured as its
two destinations. Both execute the same full API lifecycle as the native
FS/Git test. Tests use only public synthetic format fixtures.

The branch scenario uploads 270 parallel revisions of one record in batches of
eight, reads every page, continues one branch, and deletes another. It checks
competing writers with one base, rejects an invalid batch without publication,
and verifies exact wire bytes after retries. SQLite also runs this scenario
after reopening its database. Run the same scenario against PostgreSQL or a
local Worker with D1 and configured S3 destinations:

```sh
CONFIDEX_TEST_POSTGRES=postgres://user:password@127.0.0.1:5432/test \
cargo test -p confidexsyncd --test api branches::postgres_preserves -- --ignored

CONFIDEX_TEST_WORKER=http://127.0.0.1:8787 \
cargo test -p confidexsyncd --test api branches::worker_preserves -- --ignored
```

These branch tests create fresh synthetic vaults. Use disposable databases and
buckets; local Worker execution does not measure production CPU or request quotas.

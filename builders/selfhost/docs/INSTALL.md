# Self-host Confidex

This bundle contains the browser app, native Linux sync servers, a Cloudflare
Worker, configurations and the D1 schema. It contains no vaults or credentials.
No Rust compiler is required.

## Docker

```sh
docker compose up -d
```

Open `http://localhost:8080`. The web service serves the app and forwards `/v1`
to syncd. Set the app's custom synchronization URL to the same origin.
Persistent encrypted objects and the SQLite index live in the `sync-data` volume.
Back up both together. To use another storage backend, edit the syncd environment
in `compose.yaml`; the server supports mirrored S3, filesystem and Git stores.

For a public domain, put an HTTPS reverse proxy in front of port 8080. Browsers
require a secure context for cryptography and passkeys. A loopback address works
without TLS for local testing. Do not expose the syncd port separately.

Images use this release's exact tag. `latest` is also published. If the registry
package is private, authenticate with `docker login ghcr.io` or make the package
public before sharing the installation instructions.

## Native server

Choose `native/linux-ARCH-LIBC/bin/confidexsyncd`, where ARCH is `amd64` or `arm64` and
LIBC is `gnu` or `musl`. The executable needs that system libc and its normal OS
libraries. The musl build uses dynamic musl; it is not a fully static executable.

```sh
mkdir -p data
chmod +x ./native/linux-amd64-gnu/bin/confidexsyncd
./native/linux-amd64-gnu/bin/confidexsyncd syncd.toml
```

This example stores the index and encrypted objects under `./data`. Install Caddy and, in a second terminal, run `caddy run --config Caddyfile`.
It serves `web/` on port 8080 and forwards `/v1` to `127.0.0.1:8081`.
For another web server, preserve the headers and proxy rules from that file.
Use HTTPS for a public domain.

## Cloudflare Workers

Install Node.js at the version in `.node-version`, then:

```sh
npm ci
npx wrangler login
npx wrangler d1 create confidexsyncd-index
npx wrangler r2 bucket create confidexsyncd
```

Edit `cloudflare/syncd/wrangler.toml`: set the D1 database ID and S3 URL. Workers.dev is enabled by default;
custom domain routes are optional.
Create S3 API credentials for that bucket and save them as Worker secrets:

```sh
npx wrangler secret put BACKEND_S3_ACCESS_KEY_0 --config cloudflare/syncd/wrangler.toml
npx wrangler secret put BACKEND_S3_SECRET_KEY_0 --config cloudflare/syncd/wrangler.toml
npx wrangler d1 execute confidexsyncd-index --remote --file cloudflare/syncd/schema.sql --config cloudflare/syncd/wrangler.toml
npx wrangler deploy --config cloudflare/syncd/wrangler.toml
```

Deploy the app with its default Workers.dev hostname, or configure your own
routes in `cloudflare/app/wrangler.toml`:

```sh
npx wrangler deploy --config cloudflare/app/wrangler.toml
```

Select your sync hostname in the app. The Worker version stores its index in D1
and its objects in S3-compatible buckets. POSIX and Git backends need the native
server. Worker CPU, request and storage quotas still apply.

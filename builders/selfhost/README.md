# Self-host bundle builder

Assemble tested release archives into `confidex-selfhost-{version}.zip` for
Docker, native Linux or Cloudflare installation without a Rust compiler.

```sh
python3 builders/selfhost/build.py --version v1.2.3
```

Place the matching web, Worker and four Linux daemon archives in `dist/releases/`
first. The builder verifies one source version and CPU architectures, includes
licenses, configurations, D1 schema and pinned Wrangler dependencies.

The ZIP contains `web/`, `native/linux-{arch}-{libc}/`, `cloudflare/app/`,
`cloudflare/syncd/`, Compose, Caddy and server configurations. The
[installation guide](docs/INSTALL.md) becomes its root README. Tokens, vaults and
local credentials are excluded.

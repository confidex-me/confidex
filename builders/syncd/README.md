# Sync daemon Worker builder

Build the Cloudflare Worker with Rust 1.98.0, Node.js from `.node-version` and
Python 3.12+ on macOS or Linux. The builder installs and checks worker-build 0.8.7.

```sh
npm ci
python builders/syncd/build.py --version v1.2.3
npx wrangler deploy --dry-run --config apps/confidexsyncd/wrangler.toml
```

The release archive contains `index.js`, `index_bg.wasm`, licenses and source
metadata. Native daemon archives are produced by the macOS, Windows and Linux
builders. Runtime configuration and D1 setup are in the daemon README. Packaging
is local; this entry point does not deploy a Worker.

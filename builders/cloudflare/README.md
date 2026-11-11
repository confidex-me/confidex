# Cloudflare release deployment

`deploy.py` deploys the exact checked-out release's app and sync Worker archives.
The release workflow calls it after uploading artifacts.

In the application repository's GitHub Actions settings, add the secret
`CLOUDFLARE_API_TOKEN` and a variable or secret named `CLOUDFLARE_ACCOUNT_ID`.
If both exist, the variable takes precedence. The token must allow
Worker deployment and reading Worker settings in that account. Without the
token, deployment is skipped and release builds/uploads still work.

Provision the configured domains, D1 index and S3 storage first. The script
reads the existing `INDEX` D1 binding from the deployed sync Worker, keeps its
contents and preserves Worker variables and secrets, including every S3
destination. It never creates a database or applies a schema. Database IDs and
credentials stay outside source control.
The sync Worker must already have one `INDEX` D1 binding. The script does not list
D1 databases and needs no D1 metadata permissions.

For a manual run, check out the matching source, download its artifacts into
`dist/releases/`, run `npm ci`, set the two Cloudflare variables and `RELEASE_TAG`,
then run `python3 builders/cloudflare/deploy.py`. No Rust compiler is needed.

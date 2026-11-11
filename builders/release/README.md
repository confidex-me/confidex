# Existing-release uploader

`upload.py` checks every file against the release name and source-version
contract, writes `SHA256SUMS` and uploads the files to an existing GitHub Release.
It requires the GitHub CLI, `GH_TOKEN`, `GITHUB_REPOSITORY` and `RELEASE_TAG`.

The release workflow calls it after the platform builds succeed. It does not
create tags or releases and does not change the release title or notes.

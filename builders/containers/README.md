# Release container images

The release publishes `ghcr.io/confidex-me/confidexsyncd` and
`ghcr.io/confidex-me/confidex-web` for `linux/amd64` and `linux/arm64`. Each receives
the original GitHub Release tag and `latest`. Use a SemVer tag such as `v1.2.3`
or `v1.2.3-rc.1`; Docker tags cannot contain `+` build metadata.

`prepare.py` reads the tested GNU daemon archives and web archive from
`dist/releases/`. It checks source versions and ELF architectures, preserves
licenses and writes Docker contexts into `dist/containers/`.

```sh
RELEASE_TAG=v1.2.3 python3 builders/containers/prepare.py
docker build --build-arg TARGETARCH=amd64 -f builders/containers/Dockerfile.syncd -t confidexsyncd dist/containers/syncd
docker build -f builders/containers/Dockerfile.web -t confidex-web dist/containers/web
```

The daemon runs as UID/GID 10001, listens on port 8080 and stores its SQLite index
and encrypted objects in `/data`. Mount a named volume there. Git and CA
certificates support the other native storage backends. The web image serves the
app on port 8080 and proxies `/v1` to `syncd:8080`. Run both on the same Docker
network with that service name. Use HTTPS in front of public installations.
The self-host bundle supplies a complete Compose example.

On the first GHCR publication, the owner must set both packages' visibility to
**Public** in GitHub package settings. [GHCR defaults new packages to Private](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry);
a public source repository alone does not change package visibility. Later image
versions keep that setting. Public images can then be pulled without login.

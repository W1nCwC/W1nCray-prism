# Release

W1nCray-prism is GPL-3.0-or-later. Every release publishes, next to the
binaries, the complete corresponding source: `W1nCray-prism-v<x>-src.tar.gz`
(the repository at the tag plus `go mod vendor`). Both go into the same
GitHub Release.

```
bash release/build.sh v0.1.0
```

builds `dist/W1nCray-prism-linux-{amd64,arm64,armv7,386}.gz`, `SHA256SUMS` and
the source archive. The panel installs the kernel from the mirror Release
`prism-v<x>` of the W1nCray repository and verifies the SHA-256 of the asset
(the same mechanism as the other own kernels).

Build tags: `with_quic,with_wireguard,with_gvisor,with_acme`.
`-trimpath -ldflags "-s -w -X main.version=<tag>"`.

Race checks run in CI (`.github/workflows/race.yml`): the machines used to
develop the program have no C toolchain, which `-race` needs.

The source archive's `vendor/` holds what the program builds with
(`go build -mod=vendor -tags ... ./cmd/w1ncray-prism`). Test-only dependencies
are not vendored; `go test` fetches them through the module proxy.

CI: `test` (vet, tests, `-race` on `gate` and `ipc`) must pass. `race-engine`
is informational: `-race` on the engine tests reports an unsynchronised
`closed` flag inside the third-party `anytls/sing-anytls` stream (Write vs
Close, both frames inside the library); the TUIC, Hysteria and Hysteria 2
paths are clean.

#!/usr/bin/env bash
# release/build.sh <tag> — cross-build W1nCray-prism, checksums and the source archive.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

TAG="${1:?usage: release/build.sh <tag, e.g. v0.1.0>}"
TAGS="with_quic,with_wireguard,with_gvisor,with_acme,with_utls"
OUT="dist"
rm -rf "$OUT"
mkdir -p "$OUT"

build() { # goos goarch goarm name
  local goos="$1" goarch="$2" goarm="$3" name="$4" bin="$OUT/W1nCray-prism-$4"
  GOOS="$goos" GOARCH="$goarch" GOARM="$goarm" CGO_ENABLED=0 \
    go build -tags "$TAGS" -trimpath -ldflags "-s -w -X main.version=$TAG" -o "$bin" ./cmd/w1ncray-prism
  gzip -9 -n -f "$bin"
  echo "built $bin.gz"
}

build linux amd64 "" linux-amd64
build linux arm64 "" linux-arm64
build linux arm 7 linux-armv7
build linux 386 "" linux-386

(cd "$OUT" && sha256sum W1nCray-prism-*.gz > SHA256SUMS)

# The complete corresponding source: the tag plus the vendored modules.
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
git archive --format=tar --prefix="W1nCray-prism-$TAG/" HEAD | tar -x -C "$STAGE"
# Vendor what the program itself needs. Test-only dependencies (the full upstream
# protocol set the engine tests register, ~1.6 GB with cronet) are left out: the
# vendor tree is made from a copy without *_test.go, then placed next to the full
# source. `go build -mod=vendor` works; `go test` needs the module proxy.
VEND="$(mktemp -d)"
trap 'rm -rf "$STAGE" "$VEND"' EXIT
cp -r "$STAGE/W1nCray-prism-$TAG/." "$VEND/"
find "$VEND" -name '*_test.go' -delete
(cd "$VEND" && go mod vendor)
mv "$VEND/vendor" "$STAGE/W1nCray-prism-$TAG/vendor"
tar -C "$STAGE" -czf "$OUT/W1nCray-prism-$TAG-src.tar.gz" "W1nCray-prism-$TAG"
(cd "$OUT" && sha256sum "W1nCray-prism-$TAG-src.tar.gz" >> SHA256SUMS)
echo "release $TAG ready in $OUT/"

# Prism patches to mieru

Upstream: github.com/enfein/mieru/v3, version v3.39.0 (GPL-3.0-or-later,
Copyright (C) mieru authors). This directory is a copy of the upstream module
at that version, used through `replace github.com/enfein/mieru/v3 =>
./third_party/mieru` in the root go.mod. The upstream LICENSE and all copyright
headers are unchanged. Left out of the copy: `.git`, every `*_test.go`, and the
directories `test/`, `docs/`, `build/`, `deployments/`, `configs/`, `tools/`.
No protocol behavior or wire format is changed.

## Why

The library keeps two process-wide replay caches whose capacity is hard coded to
4*1024*1024 entries each, written to before decryption. Measured with one generation full: stream
about +213 MB, packet about +274 MB; a random UDP flood can fill them in
minutes, which can OOM a 512 MB host. The library has no setting for it.

## Patches

1. `pkg/replay/replay.go`: new method `(*ReplayCache).SetCapacity(capacity int)`
   appended at the end of the file (after `computeSignature`). Under the cache
   mutex it sets `capacity`; if the value changed it also empties both maps and
   restarts the expiry timer, so a smaller value frees memory. Negative values
   are ignored; 0 disables the cache (existing upstream meaning). Before: the
   capacity was fixed at construction. After: it can change at any time, thread
   safely.
2. `pkg/protocol/replay_capacity.go`: new file. Exports
   `DefaultReplayCacheEntries = 4 * 1024 * 1024` and
   `SetReplayCacheCapacity(streamEntries, packetEntries int)`, which calls
   `SetCapacity` on `streamReplayCache` and `packetReplayCache` (a value <= 0
   leaves that cache alone). Callable before or after the caches are used.
3. `pkg/protocol/underlay_stream.go:46`, `pkg/protocol/underlay_packet.go:44`:
   `replay.NewCache(4*1024*1024, ...)` became
   `replay.NewCache(DefaultReplayCacheEntries, ...)`. Same value, so the upstream
   default is kept when nothing calls the setter. The caches are still created
   at package init; no lazy creation is needed because SetCapacity resizes them.

Prism side: `inbound/mieru` option `replay_cache_entries` (core.go) calls
`SetReplayCacheCapacity` before the multiplexer starts.

## Re-applying after an upstream upgrade

1. Copy the new upstream module over `third_party/mieru` (from the module cache:
   `go mod download github.com/enfein/mieru/v3@vX.Y.Z`, then copy
   `$(go env GOMODCACHE)/github.com/enfein/mieru/v3@vX.Y.Z`), drop the same
   directories and `*_test.go` files, keep this file.
2. Redo patches 1 to 3: `grep -rn "replay.NewCache" pkg/` to find the cache
   variables (they may have moved or multiplied); re-add `SetCapacity` to
   `pkg/replay/replay.go` and `pkg/protocol/replay_capacity.go` (copy from git
   history of this directory).
3. Update the version in the root go.mod `require`, this file, NOTICE and the
   README; run `go mod tidy` and compare `go.sum` for surprises.
4. Run `go build`, `go vet`, `go test ./...` with the release tags, and
   `MIERU_MEM=1 go test ./engine/ -run TestMieruMemory/D_replay -v`.
5. If upstream makes the capacity configurable, delete the patch and the
   replace line, and map `replay_cache_entries` to the new setting.

# W1nCray-prism

The second proxy kernel of the W1nCray panel system. A single program that
serves TUIC, Hysteria, Hysteria 2, AnyTLS, NaiveProxy, VLESS, Trojan and mieru inbounds for panel
users, driven by the W1nCray agent over a local socket (see `docs/IPC.md`).

- Users are keyed by the stable panel user id and can be replaced while the
  listeners keep running; removed users lose their connections.
- Traffic is counted per user and reported with a snapshot/commit protocol.
- A config that cannot be built or started never replaces the running one.

```
w1ncray-prism run [--socket unix:/run/W1nCray-prism/prism.sock] [--state /var/lib/W1nCray-prism]
w1ncray-prism check -c config.json
w1ncray-prism version
```

License: GPL-3.0-or-later (see `LICENSE` and `NOTICE`). Releases: `docs/RELEASE.md`.

## mieru on small hosts

The mieru library keeps two process-wide replay caches (one for TCP streams, one for UDP
packets) that every received segment writes to before it is decrypted, so a flood of random
packets fills them. Upstream fixes their size at 4M entries each; a cache holds two generations,
so one full cache is about 430 to 460 MB (measured, about 55 bytes per entry), both about 0.9 GB. Since 0.3.2 the kernel carries a
patched copy of the library (`third_party/mieru`, see `PRISM-PATCHES.md` there) and the size is
the inbound option `replay_cache_entries`:

| value | meaning |
|---|---|
| absent or 0 | 1048576 entries per cache (default; worst case about 110 MB per cache, 220 MB for both) |
| 4096 to 4194304 | that many entries per cache (4194304 is the upstream size); 262144 costs at most about 30 MB per cache, 60 MB for both |
| anything else | the config is rejected and the running one stays |

Suggested values: 262144 on a 512 MB host, 1048576 on a 1 GB host, up to 4194304 on a large one.
The number of entries is the replay detection window: a cache keeps two generations of up to that
many entries and starts a new one when the current is full or after 6 minutes, so under heavy
traffic a smaller cache remembers a shorter time (never more than 12 minutes). A replayed segment older than that is no longer recognized as a replay,
which does not weaken the encryption. The caches are process-wide: with several mieru inbounds
the largest requested value is used, and the value is recomputed when an inbound starts or
stops. Changing the value drops the signatures stored so far.

Idle TCP connections are closed after 10 minutes (since 0.3.1). On a host with 512 MB or
less, also prefer the TCP transport and limit new connections per source address
(`connlimit`) or UDP packet rate (`hashlimit`) in the firewall.

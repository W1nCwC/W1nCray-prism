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

The mieru library keeps two process-wide replay caches (4M entries each, about 53 to 69
bytes per entry once full, not configurable) that every received segment writes to before
it is decrypted, so a flood of random packets can grow them to several hundred MB within
minutes. Idle TCP connections are closed after 10 minutes since 0.3.1. On a host with
512 MB or less, prefer the TCP transport and limit new connections per source address
(`connlimit`) or UDP packet rate (`hashlimit`) in the firewall.

# W1nCray-prism

The second proxy kernel of the W1nCray panel system. A single program that
serves TUIC, Hysteria, Hysteria 2, AnyTLS and NaiveProxy inbounds for panel
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

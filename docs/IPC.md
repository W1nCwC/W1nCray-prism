# Control API (IPC)

The W1nCray agent drives W1nCray-prism over HTTP/1.1 with JSON bodies on a Unix
socket (`/run/W1nCray-prism/prism.sock`, owner root, mode 0600). Both programs
define their own types; nothing is shared between the two code bases.

Every request carries `X-Prism-Api: 1`. A missing or different value is refused
with 400, so a newer agent never configures an older program by accident.

| Request | Body | Answer |
|---|---|---|
| `GET /v1/status` | – | `{api, version, core, boot_id, state, config_hash, rejected_hash, last_error, inbounds[{tag,type,users,conns}], started_at}`. `state` is `running`, `idle` (no inbound) or `failed`. `boot_id` is random per process start: when it changes the agent re-sends the config and every user table. |
| `PUT /v1/config` | `{hash, config}` | 200 `{applied, noop}`; 422 `{error:"invalid", message, kept}`; 500 `{error:"start_failed", message, kept}`. The config is parsed, checked against the allowed inbound types, built with the core's own builder (no port is bound), the user tables are handed to the new inbounds, the old core is stopped and the new one started. When it cannot start the previous config is rebuilt. Same `hash` as the running config is a no-op. A zero-inbound config is valid (`idle`). |
| `POST /v1/check` | `{config}` | 200 `{ok:true}` / 422. Builds and discards. |
| `PUT /v1/users/{tag}` | `{seq, users:[{id, uuid, speed_bps, device_limit}]}` | 200 `{applied, users, added, removed, kicked}`; 404 unknown inbound; 422 bad user. Replaces the whole set. Users are keyed by the stable panel user id. Removed users lose their live connections. A `seq` lower than the last applied one is dropped (`applied:false`); `seq` 0 always applies. |
| `PUT /v1/devices/{tag}` | `{alive:{"<uid>": n}}` | 200. The panel-wide device count per user, used with `device_limit`. |
| `GET /v1/stats?tag=` | – | `{boot_id, snapshot, traffic:[{id,up,down}], alive:[{id,ips[]}]}`. Records a snapshot of the unreported usage (it replaces any older snapshot of the tag). Nothing is subtracted yet. |
| `POST /v1/stats/commit` | `{tag, snapshot, boot_id}` | 200, or 409 when the snapshot is not the current one of the tag, was already committed, or `boot_id` differs. The recorded amounts are subtracted. |

State on disk (`--state`, default `/var/lib/W1nCray-prism`, mode 0700):
`config.json` (last good config + hash) and `users.json` (user tables with
their `seq`). They are loaded at start so the kernel serves before the agent
reconnects.

Credentials derive from the user's `uuid`: TUIC uses it as uuid and password,
Hysteria / Hysteria2 / AnyTLS use it as the password, NaiveProxy uses
`id:uuid` as HTTP basic credentials.

VLESS uses the uuid as its credential and Trojan as its password. The VLESS
flow belongs to the node, not to a user: the config carries it as the only
entry of `users` (`"users":[{"flow":"xtls-rprx-vision"}]`, no name, no uuid;
`xtls-rprx-vision` is the only flow). Any other use of `users` in a config is
refused. Trojan fallbacks are not offered.

mieru uses the user id (decimal) as user name and the uuid as password. Its
config takes `listen_port` (one port; ranges are refused), `transport`
(`tcp`, the default, or `udp`) and an optional `traffic_pattern` (base64, at
most 2048 bytes; it need not equal the client's). `users` must be absent.
Client and server clocks must differ by less than 4 minutes.

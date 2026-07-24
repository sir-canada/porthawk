# porthawk

TCPView for the browser, on Linux. One Go binary, no root.

Live table of every TCP/UDP connection and listening port with:
process attribution (all users), per-process ↓/↑ KB/s and totals since
start, country flag emoji per remote IP (offline DB — nothing leaks),
cached toggleable reverse DNS, kill button for your own processes,
click-to-copy PIDs, sortable/filterable dark UI with TCPView-style
green/red row flashes.

## Run

```sh
make dev        # build + sudo setcap + run, prints the tokened URL
```

Open the printed `http://127.0.0.1:7413/?t=…` URL. Token is stored in
`~/.config/porthawk/token` (0600); after first visit a cookie is set.

Permanent install — runs as a per-user systemd service (no root at
runtime; one `sudo` for `setcap` only):

```sh
make install    # -> ~/.local/bin + ~/.config/systemd/user, enables & starts it
```

It prints the tokened URL and enables linger so it survives logout.
Manage it with `systemctl --user {status,restart,stop} porthawk`; remove
with `make uninstall`.

The `--user` unit is deliberately **bare** — no `Protect*`/`Restrict*`/
`MemoryDenyWriteExecute`/`CapabilityBoundingSet`. In an unprivileged user
service systemd implements those via a user+mount namespace that
invalidates the binary's setcap file caps, so nethogs would lose pcap and
traffic capture would silently die. Security rests on the app itself
(loopback-only, token, same-origin WS, no root, no `CAP_KILL`). Want
systemd sandbox hardening? Run it as a **system** service with
`AmbientCapabilities=` — ambient caps survive `NoNewPrivileges`; file
caps do not. See `porthawk.service` header and git history.

## Security model

- Never runs as root. Needs exactly four capabilities
  (`cap_net_admin,cap_net_raw` for nethogs' pcap;
  `cap_dac_read_search,cap_sys_ptrace` to map sockets to any user's PID
  via `/proc/*/fd`). Granted by `setcap` file caps on the binary (the
  per-user service relies on these; the child `nethogs` carries its own).
- Binds 127.0.0.1 only. All routes need the random 256-bit token
  (cookie). WebSocket enforces same-origin — a malicious web page you
  visit cannot connect.
- Kill endpoint: kernel refuses cross-user signals (no `CAP_KILL`) and
  the server independently 403s any PID not owned by your UID.

## How it works

| Piece | Source |
|---|---|
| Connections | `/proc/net/{tcp,tcp6,udp,udp6}` parsed directly, 1 s tick |
| PID mapping | socket inode → `/proc/*/fd` readlink walk, cached, rescan on unknown inode |
| Traffic | child `nethogs -t -v1 -d 1 -a -C` — cumulative KB per PID; rates from deltas; totals survive nethogs restarts |
| Country | `phuslu/iploc` embedded IP2Location LITE DB; flag = regional-indicator codepoints; 🏠 LAN, 🔁 loopback |
| Reverse DNS | server-side, 4 workers, 1 h TTL, toggleable (persisted) |
| Push | WebSocket, full snapshot every 1 s, permessage-deflate; enrichment (traffic, DNS) skipped when no tab is open |
| Ghosts | connections scanned every tick even with no tab open; an ESTABLISHED socket that vanishes lingers as state `DISCONNECTED` for 30 s, so one that dies as you open the UI is still visible |

Traffic granularity is per **process** (kernel doesn't account per
connection); each row shows its process's rates, and the `group` view
rolls rows up under process headers.

Frontend is one dependency-free vanilla-JS file embedded in the binary —
keyed DOM patching, no framework, no build step.

## UI

- Tabs: All / Listening / Established (**default**). The Established tab
  also shows `DISCONNECTED` ghosts. Filter matches process, IP, port,
  user, country, state.
- A closed connection lingers ~30 s as a dimmed, italic `DISCONNECTED`
  ghost row (red edge) before it fades out.
- Click column headers to sort; rate/total columns default descending.
- Click a PID to copy it. Hover a row you own → ✕ (SIGTERM, then `9!`
  for SIGKILL escalation).
- `dns` toggles reverse lookups; `pause` freezes display (collection
  continues); green flash = new connection, red flash = closed.

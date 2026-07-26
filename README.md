# porthawk

TCPView for the browser, on Linux. One Go binary, no root.

Live table of every TCP/UDP connection and listening port with:
process attribution (all users), per-process ↓/↑ KB/s and totals since
start, country flag emoji per remote IP (offline DB — nothing leaks),
cached toggleable reverse DNS and opt-in IP-range ownership, your own
aliases and hide rules for remote addresses, kill button for your own
processes, click-to-copy PIDs, sortable/filterable dark UI with
TCPView-style green/red row flashes.

## Run

```sh
make dev        # build + sudo setcap + run, prints the tokened URL
```

Open the printed `http://127.0.0.1:<port>/?t=…` URL. The port is a random
five-digit one, chosen once on first run and kept in
`~/.config/porthawk/port`, so the URL stays stable across restarts; a new
one is picked only if that port has been taken by something else. Pin it
with `-listen 127.0.0.1:7413` if you want a fixed address. Token is stored
in `~/.config/porthawk/token` (0600); after first visit a cookie is set.

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

- Never runs as root. Needs four capabilities
  (`cap_net_admin,cap_net_raw` for nethogs' pcap;
  `cap_dac_read_search,cap_sys_ptrace` to map sockets to any user's PID
  via `/proc/*/fd`), plus two optional ones (`cap_bpf,cap_perfmon`) for
  per-connection UDP counters — see below. Granted by `setcap` file caps
  on the binary (the per-user service relies on these; the child
  `nethogs` carries its own).
- Binds 127.0.0.1 only. All routes need the random 256-bit token
  (cookie). WebSocket enforces same-origin — a malicious web page you
  visit cannot connect.
- Kill endpoint: kernel refuses cross-user signals (no `CAP_KILL`) and
  the server independently 403s any PID not owned by your UID.
- **Privileged actions re-authenticate at the desktop.** Blocking an
  address in ufw, or signalling a process you don't own, needs root —
  which porthawk does not have and does not gain. Those two actions are
  handed to `pkexec`, so polkit puts an authentication prompt on your
  screen and a human approves that one action. The consequences are the
  point: holding the API token is *not* enough to touch your firewall,
  because whoever holds it still cannot answer a prompt on your desktop.
  This is why it is polkit and not a `NOPASSWD` sudoers line — the latter
  would silently make the token equivalent to root. Nothing is cached,
  no privileged helper persists, the command shape is fixed in
  `elevate.go` (the client picks the action and the target, never the
  arguments), and a target must parse as a bare IP address before it is
  passed — as an argv array, never a shell string. Run with
  `-privileged=false` and the two routes are not registered at all.
- The `owner` lookup is the one feature that talks to the outside world,
  and it is **off by default**. Unlike the country flags — an embedded
  offline database, nothing leaves the machine — turning it on sends the
  remote addresses you connect to to a third party (Team Cymru's DNS
  servers, reached through your system resolver). Leave it off if that
  trade isn't worth it.
- `token`, `config.json` (`{"dns":bool,"owner":bool}`), `rules.json` and
  the `owners.json` cache all live in `~/.config/porthawk` (0700) and are
  written 0600.

## UDP/QUIC accounting (optional, recommended)

Linux keeps per-socket byte counters for TCP and **none for UDP**. Without
help, every UDP row in the table reads zero — which matters more than it
sounds, because browsers move most of their traffic over QUIC, which is
UDP. The symptom is a process row that says 2.8 KB/s sitting above
connection rows that add up to 1.9.

porthawk closes that gap with a small eBPF program (`bpf/udp.c`) that
counts bytes per socket at `udp_sendmsg` / `udpv6_sendmsg` /
`skb_consume_udp`. `make install` grants the `cap_bpf,cap_perfmon` needed
to load it.

**It is optional and porthawk works without it.** If the kernel lacks BTF,
the capabilities are missing, or the attach points have moved, the program
is skipped, startup logs why, and the settings panel repeats the reason.
In that state UDP rows stay at zero and the traffic still appears in the
per-process total — hover any group's KB/s cell for a breakdown of how
much is attributed to connections and how much is not. Nothing silently
under-reports; it just gets vaguer.

The compiled object is committed, so a plain `go build` needs no clang and
no kernel headers. It is built for the host architecture — on anything
else, run `make bpf` to regenerate (needs `clang`, `bpftool`, and a kernel
with BTF at `/sys/kernel/btf/vmlinux`), or don't, and accept the fallback.

## How it works

| Piece | Source |
|---|---|
| Connections | `/proc/net/{tcp,tcp6,udp,udp6}` parsed directly, 1 s tick |
| PID mapping | socket inode → `/proc/*/fd` readlink walk, cached, rescan on unknown inode |
| Traffic | per-socket payload bytes: TCP from `tcp_info` (`ss -ntiHO`), UDP from the optional eBPF counters. Every figure in the table is the sum of the rows beneath it — row, group header and total reconcile exactly |
| Traffic (second opinion) | child `nethogs -t -v1 -d 1 -a -C` measures *wire* bytes by packet capture: payload plus headers plus retransmits. Shown only in the KB/s tooltips, never mixed into a column with per-socket numbers |
| Local addresses | an address the kernel assigned to an interface is shown as that adapter (`10.2.2.28:37874` → `wlan0:37874`) rather than resolved; checked before DNS and ownership, outranked only by your own alias |
| Country | `phuslu/iploc` embedded IP2Location LITE DB; flag = regional-indicator codepoints; 🏠 LAN, 🔁 loopback, 🛡 VPN/tunnel route, 🏳️ unknown. Hover names it |
| Reverse DNS | server-side, 4 workers, 1 h TTL, toggleable (persisted) |
| Ownership | opt-in Team Cymru IP-to-ASN DNS for addresses reverse DNS can't name: plain TXT lookups through the system resolver, no HTTP, no API key — `<reversed-octets>.origin.asn.cymru.com` (`origin6` and reversed nibbles for v6) for the origin AS, then `AS<n>.asn.cymru.com` for its description; name taken from the organisation part (`ANTHROPIC - Anthropic, PBC, US` → `Anthropic, PBC`), AS descriptions memoised for the process; cached per **BGP-announced prefix**, so one answer names every address in the range; `~/.config/porthawk/owners.json`, 24 h TTL / 1 h when nothing announces the address / 5 min after a lookup failure; 4 workers, queries 200 ms apart (paced for the local resolver, which drops answers under a burst) |
| Rules | `~/.config/porthawk/rules.json`, hand-editable: `{"aliases":[{"match":"160.79.104.0/21","name":"Anthropic"}],"hidden":[{"match":"Anthropic"}]}` — `match` is an IP, a CIDR or a name substring, most specific network wins; also `GET`/`POST /api/rules` |
| Push | WebSocket, full snapshot every 1 s, permessage-deflate; enrichment (traffic, DNS) skipped when no tab is open |
| Ghosts | connections scanned every tick even with no tab open; an ESTABLISHED socket that vanishes lingers as state `DISCONNECTED` for a configurable window (default 45 s), so one that dies as you open the UI is still visible |

Traffic granularity is per **process** (kernel doesn't account per
connection); each row shows its process's rates, and the `group` view
rolls rows up under process headers.

Frontend is one dependency-free vanilla-JS file embedded in the binary —
keyed DOM patching, no framework, no build step.

## UI

- Tabs: All / Listening / Established (**default**). The Established tab
  also shows `DISCONNECTED` ghosts. Filter matches process, IP, port,
  user, country, state; terms are space-separated and must all match, a
  `-term` excludes, and a quoted term matches a phrase with spaces in it
  (`"google llc"`, `-"google llc"`).
- Remote column, most authoritative first: your alias → reverse DNS →
  owner → the raw IP. Each source has its own toggle, and clicking
  the cell copies the raw IP whatever is being displayed.
- Right-click any address to alias this IP, alias the whole range, hide,
  unhide, remove an alias, or push it into the filter box as an include
  or `-exclude` term.
- ⚙ opens settings: every alias and hide rule listed, editable in place
  (Enter or blur commits, Esc reverts), deletable, with a form to add one
  by hand. Writes `rules.json` immediately; the panel also follows edits
  made from the table, another tab, or the file itself.
- Hidden rows are flagged, not dropped: the top bar shows `N hidden`,
  click it to reveal them.
- Hover a flag for the country name (from the browser's
  `Intl.DisplayNames`, so no country table ships in the repo). The
  symbolic ones: 🔁 loopback, 🏠 private/LAN, 🛡 VPN/tunnel, 🏳️ unknown.
- A closed connection lingers as a dimmed, italic `DISCONNECTED` ghost row
  (red edges) before it fades out — 45 s by default, adjustable under
  Settings → Traffic (0 turns it off).
- Click column headers to sort; rate/total columns default descending.
- Click a PID or an address to copy it — the text flashes green and a
  bubble names what landed on the clipboard. Hover a row you own → ✕
  (SIGTERM, then `9!` for SIGKILL escalation).
- Keyboard: `↑`/`↓` move through the table, `Home`/`End` jump to the ends,
  `→`/`Enter` expand a group (`→` again steps into it), `←` collapses or
  jumps out to the group header, `Ctrl-C` copies the highlighted address,
  `Ctrl-Shift-C` the whole row, `Esc` drops the highlight. Collapsed groups
  are skipped, since their members aren't on screen.
- `dns` toggles reverse lookups, `owner` range ownership, `alias` whether
  saved aliases are shown; `pause` freezes display (collection
  continues); green flash = new connection, red flash = closed.

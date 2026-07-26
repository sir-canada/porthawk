# AGENTS.md

Working notes for agents editing this repo. Read `README.md` for what
tool is and its security model; this file is about building, restarting
not breaking things.

## Rebuild + restart (the thing you'll do every time)

Check first whether it's running as installed user service:

```sh
systemctl --user is-active porthawk    # "active" -> installed unit
```

**Installed (service) — usual case:**

```sh
make restart                    # build + setcap + install unit + restart
```

`make install` alone is not enough: it runs `systemctl --user enable
--now`, which does **not** restart an already-running unit, so the old
binary keeps serving. `make restart` is `install` plus explicit
`systemctl --user restart`.

**Ad-hoc foreground run (no service):**

```sh
make dev        # build + sudo setcap + run in this terminal; prints tokened URL
```

Both need one `sudo`for `setcap` only. Nothing runs as root.

### Verify

```sh
systemctl --user status porthawk --no-pager   # expect porthawk + a nethogs child
journalctl --user -u porthawk -n 30 --no-pager
```

 URL, w/ token:

```sh
echo "http://127.0.0.1:$(cat ~/.config/porthawk/port)/?t=$(cat ~/.config/porthawk/token)"
```

Snapshots are pushed over `/ws` WebSocket once second — there is **no
JSON endpoint to curl**. To check labelling/parsing change w/o
browser, call fn from throwaway `_test.go` against live PIDs
(see below) rather than trying to scrape HTTP.

## Gotchas

- **setcap is per-inode: every rebuild drops caps.** Rebuilding by hand
  (`go build`) and restarting gives binary w/ no capabilities — nethogs
  loses pcap and traffic silently reads zero, sockets of other users stop
  mapping to PIDs. Always go through `make dev` / `make install`.
- **Don't add `Protect*`/`Restrict*`/`NoNewPrivileges`/`CapabilityBoundingSet`
  to `porthawk.service`.** In `--user` unit systemd implements those
  w/ user+mount namespace, which invalidates binary's file caps.
  bare unit is deliberate; header comment in `porthawk.service` and git
  history explain it. Hardening belongs in *system* unit using
  `AmbientCapabilities=`.
- Capabilities needed: `cap_net_admin,cap_net_raw` (nethogs pcap)
  `cap_dac_read_search,cap_sys_ptrace` (reading `/proc/*/fd`
  `/proc/*/exe` of other users' processes). Code that reads new `/proc`
  paths for arbitrary PIDs relies on these two.
- **Never widen what server itself may do.** Two actions need root —
  `ufw` blocking and signalling another user's process — and both go
  through `pkexec` so polkit authenticates each one at desktop
  (`elevate.go`). Do not "simplify" this into sudoers `NOPASSWD` entry,
   setuid binary, or privileged helper daemon: each of those turns
  possession of API token into root, which is exactly what
  current design prevents. unprivileged `handleKill` keeps its
  same-user 403 — `handleKillRoot` is separate route, not relaxation
  of that check.
- **Anything reaching privileged process is validated, not escaped.**
  block target must parse as bare `netip.Addr` (no CIDR, no hostname,
  no ufw keyword) and is re-rendered from parsed form; command is
   fixed argv array built in `ufwArgs`never shell string. Tests in
  `elevate_test.go` pin exact argv and rejected inputs — keep
  them passing.
- **Every way to signal process goes through `killGuard`.** ✕
  button, both context-menu entries and their as-root counterparts. It is
  one fn on purpose: second code path that skips prompt is
   bug this prevents. Off by preference (`porthawk.confirmkill`), on
  by default — misclick should cost dialog, not process.
- Loopback + token only. Keep it that way: no new routes outside
  `s.auth(...)`no binding off `127.0.0.1`no relaxing WebSocket
  same-origin check.
- `web/index.html` is `go:embed`ed — editing it needs rebuild, not
  browser refresh.

## Traffic numbers: one unit in the table, and they add up exactly

**The table shows payload bytes from per-socket kernel counters,
every level is sum of level below it.** Row → group header →
table total, exactly, no fudge. Verified: `sumConns` is only
aggregator in `web/index.html`used for `g.agg` and for top totals.

- TCP payload from `tcp_info` (`tcpstats.go`)
- UDP payload from eBPF (`udpstats.go`)

Both were checked against known byte count (send exactly 2,000,000
bytes over loopback, compare): **0.00% error, both protocols, both
directions**. Datagrams kernel drops are correctly *not*
counted — `skb_consume_udp` fires on delivery, not arrival.

`nethogs` still runs, but it is **no longer what any table cell shows**.
It measures something different — wire bytes: payload plus TCP/IP headers
plus retransmits, every protocol. It survives as labelled second
opinion in KB/s tooltips (`wireNote`). Do not mix it back into
column w/ per-socket numbers; that mismatch is exactly what made
table look broken.

Expect payload to sit below wire, by lot in one direction: measured
against `/proc/net/dev` under load, downloads run ~95% of wire, uploads
~54%, b/c download's uplink is nearly all pure ACKs — header w/
no payload. That is physics, not leak.

- **Everything derives from `snap.conns`.** If number ever needs to
  come from somewhere else, it will stop adding up. Don't.
- **`g.sortv` is `g.agg`.** group of one renders as bare connection
  row rather than header, so sorting and display must use same
  numbers. They previously didn't, and idle `ssh` sorted to top of
   KB/s sort showing blank cell.
- **Cumulative totals live in stats structs, not on `Conn`.** Rows
  are rebuilt from `/proc` every tick, `c.UpKB = e.upKB` (assign from
   running total), never `+=`. `udpstats.go` had this bug: totals read
  as one tick's delta, so socket that moved 2 MB displayed whatever it
  did in last second.
- **UDP accounting is optional and must stay optional.** `NewUDPStats`
  never returns error and never fatals: no BTF, no `cap_bpf` /
  `cap_perfmon`or kernel that moved `udp_sendmsg` /
  `skb_consume_udp` all mean `Available() == false`UDP rows read zero,
  and `Snapshot.UDPAcct` tells UI to say so. Probes attach
  individually so losing one direction doesn't cost other.
- **The eBPF object is committed; `bpf/vmlinux.h` is not.** Plain
  `go build` must keep working w/ no clang and no kernel headers. Only
  `make bpf` needs those, and only when `bpf/udp.c` changes or target
  architecture does.
- **The BPF map is keyed by 4-tuple to match `/proc/net/udp`**, not by
  socket inode — that's what lets `connUDPKey` join onto rows scanner
  already built. Unconnected sockets have zero remote on both sides,
  they line up w/o special case.
- **First `Apply` after startup only baselines.** Same rule as
  `tcpstats.go`w/o it long-lived socket dumps its lifetime total
  into one tick as fake spike.

## Layout

| File | Role |
|---|---|
| `main.go` | HTTP/WS server, token auth, 1 s snapshot broadcast loop |
| `conns.go` | `/proc/net/{tcp,tcp6,udp,udp6}` parsing, socket inode → PID, `Conn` (the row shipped to the UI), `NoPID` reason + blocked-process count |
| `procinfo.go` | app naming: cgroup scope, exe install path, cwd instances, ssh peer |
| `nethogs.go` | child `nethogs -t -v1` parser → per-process cumulative KB + rates |
| `tcpstats.go` | per-connection bytes from `ss -ti` (TCP only; UDP is `udpstats.go`'s job) |
| `udpstats.go` + `bpf/udp.c` | optional eBPF per-socket UDP byte counters; degrades to "unavailable" and never blocks startup |
| `iface.go` | local addresses → the adapter they're assigned to (`10.2.2.28` → `wlan0`) |
| `ghosts.go` | keeps vanished ESTABLISHED conns visible as DISCONNECTED for a configurable window (default 45 s, 0 = off) |
| `dns.go` | cached, toggleable reverse DNS, server-side |
| `owner.go` | IP-range ownership via Team Cymru's IP-to-ASN DNS: per-BGP-prefix cache, `owners.json`, `/api/owner` |
| `rules.go` | user aliases + hide rules, `rules.json`, `/api/rules` |
| `geo.go` | offline IP → country (`phuslu/iploc`) + VPN-interface detection |
| `kill.go` | `/api/kill`, UID-checked before `kill(2)` |
| `web/index.html` | the entire frontend, embedded |

## Process naming (`procinfo.go`)

Where "which app is this?" is decided. Order in `appIdentity`cwd-keyed CLI
instance → cgroup app scope → exe install path → `ssh user@host` → `""`
(caller falls back to `comm`).

Rules to preserve when touching it:

- **`comm` is not app name.** Self-updating tools run from versioned
  files — Claude Code's exe is `~/.local/share/claude/versions/2.1.217`
  its `comm` is `2.1.217`. Never key behaviour on `comm` alone.
- **The known-app table is cosmetic, not gate.** `knownApp()` exists only
  to fix casing and vendor/product mismatches (`cendio.tlclient` →
  `ThinLinc`). app that isn't listed must still be named, from its own
  bundle dir. Never make recognition precondition for label.
- **Reject by meaninglessness, not by allow-list.** `genericDir()` filters
  container directories (`bin` `lib`multiarch triplets, `flatpak`
  version dirs, …). Adding app to table is almost never right fix
  for bad label; right fix is better generic rule.
- Terminal emulators return `""` from `friendly()` on purpose: shell
  ssh started from terminal inherits its cgroup scope but is not "the
  terminal".

Tests are pure-fn throughout and need neither live processes nor
network: `procinfo_test.go` (`exeAppPath` `versionDir` `friendly`),
`rules_test.go` (alias/hide matching, persistence), `owner_test.go` (Cymru
answer parsing and cache precedence — never call `query` `Start`
anything that would reach network from test):

```sh
go vet ./... && go test ./... && gofmt -l .
```

To sanity-check against real processes, scratch test is cheapest way
in — delete it afterwards:

```go
func TestLive(t *testing.T) { t.Log(appIdentity(1234, "ssh")) }
```

## Naming remote addresses (`owner.go`, `rules.go`, `iface.go`)

 Remote column resolves in one order — alias → local adapter → reverse
DNS → owner → raw IP — and each network source has its own toggle,
every step has to work
w/ others switched off. broadcast loop reflects that: owner
lookup is only asked about addresses reverse DNS failed to name,
rules are applied last, so alias overrides both and hide rules can
match whatever names row ended up w/.

- **An address on one of our own interfaces is named by that adapter,
  and that check runs first.** `iface.go` maps kernel-assigned addresses
  to adapter names (`10.2.2.28` → `wlan0`), and hit short-circuits both
  reverse DNS and owner: PTR would hand back machine hostname —
  identical for every interface, so useless on multi-homed box —
  private address has no owner to find. Only user alias outranks it.
  No toggle: it reads local interface table, never network,
  there is nothing to leak and nothing to pace. Map is rebuilt on
  `ifaceTTL` (10 s) so VPNs coming up and DHCP renewals land,
  failed enumeration keeps previous map rather than un-naming
  everything.
- **One instance per config dir, enforced by `flock`.** Taken in
  `main` before `listen()`, held for process lifetime via package
  var `lockFile` (`os.File` finalizer closes fd = drops lock, so the
  reference must outlive the function). Two copies sharing a config
  dir fight over `port` file: newcomer finds saved port busy, picks
  another, writes it back — published URL then names wrong process,
  and a pre-upgrade stray keeps serving old build from own transient
  unit where `systemctl restart` can't reach it. Don't replace w/
  pidfile: flock is released by kernel even on SIGKILL.
- **Optional deps report, they don't retry forever.** `nethogs`
  missing = permanent, `exec.LookPath` first, say it once, stop
  (was 3 s retry forever ≈ 29k journal lines/day). Real crashes
  back off 3 s → 2 min, reset after a run that lasted > 30 s.
  Reason goes to UI via `Hogs.Why()`/`hogsWhy`, same channel as
  `UDPWhy`.
- **`PID == -1` has three causes, don't collapse them.** `inode == 0`
  means kernel keeps no owner (TIME_WAIT — reported as uid 0, so row
  reads `root`; harmless). Inode set but unmapped means either we
  were refused `/proc/<pid>/fd` (`denied` — real fault, needs caps) or
  process exited mid-scan (`gone`). `walkProc` counts EACCES into
  `Scanner.blocked`; `Conn.NoPID` carries reason to UI. Silent
  degradation here is what made "phantom root process" reports
  unanswerable — keep it loud.
- **`Apply` recomputes `c.Hide`it never accumulates it.** flag is
  cleared at top of every call, b/c `Apply` also runs over ghost
  rows — frozen copies carrying whatever was true when socket died.
  w/o reset, rule you deleted kept hiding those rows for
   ghost's full linger window. `main.go` re-applies rules to ghost tail
  after `ghosts.Track` for same reason.
- **Owner exclusions match ownership only.** `exclStrs` is checked
  against `c.Owner`/`c.LOwner` and deliberately not against `Host`
  `RAddr`excluding "Cloudflare" must not catch host that merely has
   word in its PTR record. That narrowness is whole difference
  btw this list and hide rule — don't "improve" it by widening.
- **`Rule.Off` parks rule instead of deleting it.** Compiled matchers
  skip `Off` entries, so semantics live in `compileLocked`
  nowhere else. Retyping owner name to get rule back is exactly
  friction that stops people curating list.
- **Hide flags row, it does not drop it.** server still ships
  hidden rows w/ `hide` set; UI counts them ("N hidden")
  reveals them w/ no round trip. Filtering them out server-side would
  make count unknowable and turn unhiding into reload.
- **The backend is Team Cymru's IP-to-ASN DNS, and RDAP is not
  option.** `origin.asn.cymru.com` / `origin6.asn.cymru.com` give
  origin AS, `AS<n>.asn.cymru.com` its description; plain TXT through
  system resolver, so resolver caches on top of our cache.
  rdap.org redirector allows 10 requests per 10 seconds and its own docs
  send regular clients elsewhere — connection table holds more
  unresolved addresses than that in one tick. Don't switch it back.
- **Answers are cached per BGP-announced prefix**, not per registry
  allocation and not per IP: one answer names every address in
  announced range. AS descriptions are memoised per AS number for
  process lifetime.
- **The three TTLs are not interchangeable.** `ownerTTL` 24 h for
  resolved name, `ownerNegTTL` 1 h when nothing announces address,
  `ownerFailTTL` 5 min after timeout or SERVFAIL: failed lookup must
  never be cached as "this address has no owner".
- **The 200 ms pacing exists for *local* resolver, not for Cymru.**
  cold cache has dozens of addresses to name at once; at 50 ms stub
  resolver dropped answers and two thirds of first batch cached as
  failures. Measure cold start (`rm ~/.config/porthawk/owners.json`
  restart, count entries w/ empty name) before speeding it up.
- **`owner` defaults off, and that's privacy decision.** It is only
  thing here that leaves machine: remote addresses you connect to
  go to Cymru's DNS servers, by way of your system resolver. Don't enable
  it implicitly, and don't query before toggle is on.
- **`rules.json`  `owners.json` are written temp-file + rename.** Both
  are user data — aliases built up by hand, cache that costs paced
  network round-trips to rebuild — and torn write loses it. New writers
  stay atomic and 0600.

## Delegation

Don't grep and read this repo from main thread — it evicts plan.
Send recon to `scout` subagent (`.claude/agents/scout.md`): it returns
file paths, line ranges, key code, and constraints. Then edit from that.

- One scout per area of change; independent ones launch concurrently.
- Follow-up questions go back to *same* scout by name (`SendMessage`);
   new spawn re-reads everything.
- Scout never edits. Edits, architecture, naming, and security
  invariants in Gotchas stay in main thread.

## Conventions

- Standard library plus few deps already in `go.mod`no framework, no
  new dependency w/o reason.
- Comments explain *why* (the non-obvious kernel/systemd/proc behaviour),
  not what line does.
- Anything that reads `/proc` must tolerate process vanishing mid-read:
  errors mean "skip this PID", never fatal.


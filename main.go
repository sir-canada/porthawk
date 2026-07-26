package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coder/websocket"
)

//go:embed web/index.html
var webFS embed.FS

type Snapshot struct {
	T     int64     `json:"t"`
	Me    int       `json:"me"`    // our uid: rows we may kill
	DNS   bool      `json:"dns"`   // resolver toggle state
	Owner bool      `json:"owner"` // ownership lookup toggle state
	Rules rulesFile `json:"rules"` // user aliases + hide rules
	Cfg   string    `json:"cfg"`   // config dir, shown in settings
	// UDPAcct reports whether UDP rows carry real per-socket numbers. Off
	// means the eBPF counters could not be loaded and UDP traffic shows
	// only in the per-process total — the UI says so rather than letting
	// the zeros read as "this connection is idle".
	UDPAcct bool   `json:"udpAcct"`
	UDPWhy  string `json:"udpWhy,omitempty"`
	// Priv tells the UI whether to offer the actions that need a desktop
	// authentication prompt. Off means the routes are not even registered.
	Priv bool `json:"priv"`
	// GhostTTL is the DISCONNECTED linger window in seconds, echoed back so
	// a reload or a second tab shows the value actually in force rather
	// than whatever that browser last typed.
	GhostTTL int `json:"ghostTTL"`
	// AttrBlocked counts processes that refused us /proc/<pid>/fd on the
	// last walk. Non-zero means unattributed rows are a missing capability,
	// not a mystery.
	AttrBlocked int    `json:"attrBlocked"`
	Caps        string `json:"caps"` // capability list the fix needs
	// HogsWhy explains missing per-process totals (nethogs absent or
	// crashing), "" when they are live.
	HogsWhy string           `json:"hogsWhy,omitempty"`
	Totals  ProcStat         `json:"totals"`
	Procs   map[int]ProcStat `json:"procs"`
	Conns   []Conn           `json:"conns"`
}

type server struct {
	token      string
	cfgDir     string
	resolver   *Resolver
	owner      *Owner
	ifaces     *Ifaces
	rules      *Rules
	scanner    *Scanner
	hogs       *Hogs
	tcp        *TCPStats
	udp        *UDPStats
	ghosts     *Ghosts
	privileged bool

	mu      sync.Mutex
	clients map[*websocket.Conn]context.CancelFunc
}

func main() {
	addr := flag.String("listen", "",
		"listen address (keep on loopback); empty picks a persistent random port")
	// Privileged actions are gated by a desktop authentication prompt, but
	// on a machine where nobody should ever be offered them, not
	// registering the routes at all is a stronger statement than relying
	// on polkit to refuse.
	privileged := flag.Bool("privileged", true,
		"offer actions that authenticate via polkit (ufw block, kill another user's process)")
	flag.Parse()
	log.SetFlags(log.Ltime)

	cfgDir, err := os.UserConfigDir()
	if err != nil {
		log.Fatal(err)
	}
	cfgDir = filepath.Join(cfgDir, "porthawk")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		log.Fatal(err)
	}

	// Refuse to be a second copy before anything else happens. Two
	// instances sharing a config dir fight over the port file: the newcomer
	// finds the saved port occupied by the incumbent, picks another, and
	// writes that back — so the "stable" URL drifts on every restart. The
	// thing most likely to be holding porthawk's port is another porthawk.
	if !singleInstance(cfgDir) {
		log.Print("porthawk is already running; not starting a second copy")
		if u := runningURL(cfgDir); u != "" {
			log.Printf("open the running one at: %s", u)
		}
		return
	}

	prefs := loadPrefs(cfgDir)
	s := &server{
		token:   loadToken(cfgDir),
		cfgDir:  cfgDir,
		rules:   NewRules(cfgDir),
		scanner: NewScanner(),
		hogs:    NewHogs(),
		tcp:     NewTCPStats(),
		ghosts:  NewGhosts(prefs.ghostTTL),
		clients: map[*websocket.Conn]context.CancelFunc{},
	}
	s.resolver = NewResolver(prefs.dns)
	s.owner = NewOwner(cfgDir, prefs.owner)
	s.ifaces = NewIfaces()
	// Optional: real per-socket UDP counters when the kernel allows it.
	// Everything works without it, just with UDP rows reading zero.
	s.udp = NewUDPStats()
	if s.udp.Available() {
		defer s.udp.Close()
	} else {
		log.Printf("udp accounting off — %s", s.udp.Why())
		log.Printf("udp accounting: UDP/QUIC traffic will show in per-process totals only")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go s.hogs.Run(ctx)
	s.resolver.Start(ctx)
	s.owner.Start(ctx)
	go s.broadcastLoop(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.auth(s.handleIndex))
	mux.HandleFunc("/ws", s.auth(s.handleWS))
	mux.HandleFunc("/api/kill", s.auth(handleKill))
	mux.HandleFunc("/api/dns", s.auth(s.handleDNS))
	mux.HandleFunc("/api/owner", s.auth(s.handleOwner))
	mux.HandleFunc("/api/rules", s.auth(s.handleRules))
	mux.HandleFunc("/api/ghostttl", s.auth(s.handleGhostTTL))
	// Privileged actions. Each one re-authenticates through polkit at the
	// desktop, so the token alone can never reach them (see elevate.go).
	if *privileged {
		mux.HandleFunc("/api/block", s.auth(s.handleBlock))
		mux.HandleFunc("/api/killroot", s.auth(s.handleKillRoot))
	} else {
		log.Print("privileged actions disabled (-privileged=false)")
	}
	s.privileged = *privileged

	ln, err := listen(*addr, cfgDir)
	if err != nil {
		log.Fatal(err)
	}

	srv := &http.Server{Handler: mux}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()

	log.Printf("porthawk ready:  http://%s/?t=%s", ln.Addr(), s.token)
	if err := srv.Serve(ln); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

// ---- single instance ----

// lockFile is kept alive for the process lifetime on purpose: os.File has
// a finalizer that closes the descriptor, and closing it drops the lock.
var lockFile *os.File

// singleInstance takes an exclusive advisory lock on the config dir. The
// lock is per config dir, so two instances with different -listen and
// different XDG_CONFIG_HOME still work; only copies that would tread on
// each other's state are refused.
//
// flock is released by the kernel when the process dies, so a crash or a
// SIGKILL cannot leave a stale lock behind — no PID file to go stale, no
// "is that PID still ours?" guessing.
func singleInstance(cfgDir string) bool {
	f, err := os.OpenFile(filepath.Join(cfgDir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return true // cannot lock: a missing guard is better than no startup
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return false
	}
	lockFile = f
	return true
}

// runningURL reconstructs the incumbent's address from the shared config
// dir, so the duplicate can point the user at the instance that already
// exists instead of just refusing.
func runningURL(cfgDir string) string {
	port, err := os.ReadFile(filepath.Join(cfgDir, "port"))
	if err != nil {
		return ""
	}
	tok, err := os.ReadFile(filepath.Join(cfgDir, "token"))
	if err != nil {
		return ""
	}
	return "http://127.0.0.1:" + strings.TrimSpace(string(port)) + "/?t=" + strings.TrimSpace(string(tok))
}

// ---- listener ----

// Port range for the automatic port: five digits, above the range the
// kernel hands out for ephemeral source ports on a default Linux box
// (32768-60999), so a random pick is unlikely to collide with an outgoing
// connection that happens to be borrowing the number.
const (
	minPort = 61000
	maxPort = 65535
)

// listen binds the UI socket. An explicit -listen is used verbatim.
// Otherwise the port from the config dir is reused, and only if that port
// is gone does a new random one get picked and written back — the URL a
// user bookmarks keeps working across restarts.
//
// The port is proven free by binding it, and the same listener is what the
// server then serves on, so nothing can take it in between.
func listen(addr, cfgDir string) (net.Listener, error) {
	if addr != "" {
		return net.Listen("tcp", addr)
	}

	p := filepath.Join(cfgDir, "port")
	if b, err := os.ReadFile(p); err == nil {
		if port, err := strconv.Atoi(string(b)); err == nil && port >= minPort && port <= maxPort {
			if ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port)); err == nil {
				return ln, nil
			}
			log.Printf("saved port %d is in use — picking another", port)
		}
	}

	// Random rather than sequential so a second instance, or a fresh
	// install on a machine that already runs one, doesn't march predictably
	// through the range.
	span := big.NewInt(maxPort - minPort + 1)
	for tries := 0; tries < 200; tries++ {
		n, err := rand.Int(rand.Reader, span)
		if err != nil {
			return nil, err
		}
		port := minPort + int(n.Int64())
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			continue // taken, try another
		}
		if err := os.WriteFile(p, []byte(strconv.Itoa(port)), 0o600); err != nil {
			ln.Close()
			return nil, err
		}
		return ln, nil
	}
	return nil, errors.New("no free port found in " +
		strconv.Itoa(minPort) + "-" + strconv.Itoa(maxPort))
}

// ---- auth ----

func loadToken(dir string) string {
	p := filepath.Join(dir, "token")
	if b, err := os.ReadFile(p); err == nil && len(b) >= 32 {
		return string(b)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		log.Fatal(err)
	}
	tok := hex.EncodeToString(raw)
	if err := os.WriteFile(p, []byte(tok), 0o600); err != nil {
		log.Fatal(err)
	}
	return tok
}

func (s *server) tokenOK(v string) bool {
	return len(v) == len(s.token) &&
		subtle.ConstantTimeCompare([]byte(v), []byte(s.token)) == 1
}

// auth accepts ?t=<token> (sets cookie, redirects clean) or the cookie.
func (s *server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if t := r.URL.Query().Get("t"); t != "" {
			if !s.tokenOK(t) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name: "porthawk", Value: t, Path: "/",
				HttpOnly: true, SameSite: http.SameSiteStrictMode,
			})
			http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
			return
		}
		if c, err := r.Cookie("porthawk"); err == nil && s.tokenOK(c.Value) {
			next(w, r)
			return
		}
		http.Error(w, "unauthorized — open the URL printed at startup", http.StatusUnauthorized)
	}
}

// ---- handlers ----

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, _ := webFS.ReadFile("web/index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}

func (s *server) handleWS(w http.ResponseWriter, r *http.Request) {
	// Accept enforces same-origin by default: blocks malicious web pages.
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionContextTakeover,
	})
	if err != nil {
		return
	}
	// Block here for the lifetime of the socket: returning from the
	// handler cancels r.Context(), which would kill the connection.
	ctx, cancel := context.WithCancel(r.Context())
	s.mu.Lock()
	s.clients[c] = cancel
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.clients, c)
		s.mu.Unlock()
		cancel()
		c.Close(websocket.StatusNormalClosure, "")
	}()
	// Drain reads until close/error.
	for {
		if _, _, err := c.Read(ctx); err != nil {
			return
		}
	}
}

func (s *server) handleDNS(w http.ResponseWriter, r *http.Request) {
	if v, ok := readToggle(w, r); ok {
		s.resolver.SetEnabled(v)
		savePref(s.cfgDir, "dns", v)
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleOwner toggles RDAP ownership lookups. Off by default: unlike the
// offline geo database, this one sends addresses you connect to out to a
// third party.
func (s *server) handleOwner(w http.ResponseWriter, r *http.Request) {
	if v, ok := readToggle(w, r); ok {
		s.owner.SetEnabled(v)
		savePref(s.cfgDir, "owner", v)
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleGhostTTL sets how long DISCONNECTED rows linger. The value is
// clamped rather than rejected — the UI number input can be typed into
// freely, and a silently corrected 9999 is friendlier than an error the
// panel would have to find somewhere to display.
func (s *server) handleGhostTTL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Seconds int `json:"seconds"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64)).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	d := clampGhostTTL(time.Duration(body.Seconds) * time.Second)
	s.ghosts.SetTTL(d)
	savePref(s.cfgDir, "ghostTTL", int(d/time.Second))
	w.WriteHeader(http.StatusNoContent)
}

// readToggle decodes {"enabled": bool} from a POST, writing the error
// response itself if the request is malformed.
func readToggle(w http.ResponseWriter, r *http.Request) (bool, bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false, false
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64)).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return false, false
	}
	return body.Enabled, true
}

// ---- snapshot broadcast ----

func (s *server) broadcastLoop(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		s.mu.Lock()
		n := len(s.clients)
		s.mu.Unlock()

		// Scan every tick, even with nobody watching, so ghosts of
		// connections that die before the UI opens are already tracked.
		// The costly enrichment (per-socket traffic, reverse DNS) is
		// still gated to when a client is actually connected.
		conns := s.scanner.Scan()
		if n > 0 {
			s.tcp.Apply(conns)
			s.udp.Apply(conns) // no-op when the eBPF counters aren't loaded
			for i := range conns {
				c := &conns[i]
				// An alias the user pinned to an IP or a range is the
				// last word on what that address is called, so don't
				// look it up at all: no reverse DNS, no RDAP. Only the
				// IP/CIDR rules can short-circuit like this — a
				// name-substring alias rule matches on the very names
				// these lookups produce, so those still have to wait
				// for rules.Apply below.
				// Before any lookup: if the address is assigned to one of
				// our own interfaces, the adapter that owns it is the
				// answer. It is free, exact, and beats what reverse DNS
				// would say (the machine's hostname, identical for every
				// interface) or what ownership would say (nothing, for a
				// private address). Only a user alias outranks it.
				c.Iface = s.ifaces.Name(c.RAddr)
				c.LIface = s.ifaces.Name(c.LAddr)

				c.Alias = s.rules.AliasFor(c.RAddr)
				if c.Alias == "" && c.Iface == "" {
					c.Host = s.resolver.Lookup(c.RAddr)
					// Ownership is the fallback for addresses reverse
					// DNS can't name, so only ask about those: no point
					// paying an RDAP lookup for a host we can already
					// name.
					if c.Host == "" {
						c.Owner = s.owner.Lookup(c.RAddr)
					}
				}
				// Cache-only, never enqueues, so it stays cheap even for
				// aliased rows — and the UI needs it for "alias range".
				c.Pfx = s.owner.Prefix(c.RAddr)
				// Same treatment for the local end. Owner lookups skip
				// private/loopback addresses on their own, so a LAN
				// address costs nothing here.
				c.LAlias = s.rules.AliasFor(c.LAddr)
				if c.LAlias == "" && c.LIface == "" {
					c.LHost = s.resolver.Lookup(c.LAddr)
					if c.LHost == "" {
						c.LOwner = s.owner.Lookup(c.LAddr)
					}
				}
				// Rules last: hide rules match against whatever names
				// the row ended up with, and the name-substring alias
				// rules need the lookups to have happened.
				s.rules.Apply(c)
			}
		}
		nLive := len(conns)
		conns = s.ghosts.Track(conns)
		if n == 0 {
			continue // tracking done; nobody to send to
		}
		// Ghost rows are frozen copies of sockets that have already died,
		// so they carry the rule flags that were true at the time. Rules
		// are live state — a hide rule deleted a second ago must stop
		// applying now, not whenever the ghost window expires — so
		// re-evaluate them against the current rules.
		for i := nLive; i < len(conns); i++ {
			s.rules.Apply(&conns[i])
		}
		procs, totals := s.hogs.Snapshot()
		// Attach recognizable app labels to per-process stats so the UI can
		// group traffic by app (matches the App field on connections).
		for pid, p := range procs {
			if p.App == "" {
				p.App = s.scanner.App(pid)
				procs[pid] = p
			}
		}
		snap := Snapshot{
			T: time.Now().UnixMilli(), Me: os.Getuid(),
			DNS: s.resolver.Enabled(), Owner: s.owner.Enabled(),
			Rules: s.rules.Snapshot(), Cfg: s.cfgDir, Totals: totals,
			UDPAcct: s.udp.Available(), UDPWhy: s.udp.Why(),
			Priv:        s.privileged,
			GhostTTL:    int(s.ghosts.TTL() / time.Second),
			AttrBlocked: s.scanner.Blocked(), Caps: capsNeeded,
			HogsWhy: s.hogs.Why(),
			Procs:   procs, Conns: conns,
		}
		buf, err := json.Marshal(snap)
		if err != nil {
			continue
		}

		s.mu.Lock()
		for c := range s.clients {
			wctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			if err := c.Write(wctx, websocket.MessageText, buf); err != nil {
				if cf := s.clients[c]; cf != nil {
					cf()
				}
				delete(s.clients, c)
			}
			cancel()
		}
		s.mu.Unlock()
	}
}

// ---- prefs ----

type prefs struct {
	dns      bool          // reverse DNS (default on: your resolver already sees this traffic)
	owner    bool          // RDAP ownership (default off: it queries a third party)
	ghostTTL time.Duration // how long DISCONNECTED rows linger; 0 disables them
}

func prefsPath(dir string) string { return filepath.Join(dir, "config.json") }

func loadPrefs(dir string) prefs {
	p := prefs{dns: true, owner: false, ghostTTL: defaultGhostTTL}
	b, err := os.ReadFile(prefsPath(dir))
	if err != nil {
		return p
	}
	var c struct {
		DNS      *bool `json:"dns"`
		Owner    *bool `json:"owner"`
		GhostTTL *int  `json:"ghostTTL"` // seconds
	}
	if json.Unmarshal(b, &c) == nil {
		if c.DNS != nil {
			p.dns = *c.DNS
		}
		if c.Owner != nil {
			p.owner = *c.Owner
		}
		if c.GhostTTL != nil {
			p.ghostTTL = clampGhostTTL(time.Duration(*c.GhostTTL) * time.Second)
		}
	}
	return p
}

// savePref updates one key, preserving the others already in the file.
// The decoded map is map[string]any rather than map[string]bool because
// the file holds numbers as well as toggles now — decoding into the
// narrower type would fail on the whole file and silently drop every
// other setting the next time a toggle was flipped.
func savePref(dir string, key string, v any) {
	m := map[string]any{}
	if b, err := os.ReadFile(prefsPath(dir)); err == nil {
		json.Unmarshal(b, &m)
	}
	m[key] = v
	b, _ := json.Marshal(m)
	os.WriteFile(prefsPath(dir), b, 0o600)
}

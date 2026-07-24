package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/coder/websocket"
)

//go:embed web/index.html
var webFS embed.FS

type Snapshot struct {
	T      int64            `json:"t"`
	Me     int              `json:"me"`  // our uid: rows we may kill
	DNS    bool             `json:"dns"` // resolver toggle state
	Totals ProcStat         `json:"totals"`
	Procs  map[int]ProcStat `json:"procs"`
	Conns  []Conn           `json:"conns"`
}

type server struct {
	token    string
	cfgDir   string
	resolver *Resolver
	scanner  *Scanner
	hogs     *Hogs
	tcp      *TCPStats
	ghosts   *Ghosts

	mu      sync.Mutex
	clients map[*websocket.Conn]context.CancelFunc
}

func main() {
	addr := flag.String("listen", "127.0.0.1:7413", "listen address (keep on loopback)")
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

	s := &server{
		token:   loadToken(cfgDir),
		cfgDir:  cfgDir,
		scanner: NewScanner(),
		hogs:    NewHogs(),
		tcp:     NewTCPStats(),
		ghosts:  NewGhosts(),
		clients: map[*websocket.Conn]context.CancelFunc{},
	}
	s.resolver = NewResolver(loadDNSPref(cfgDir))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go s.hogs.Run(ctx)
	s.resolver.Start(ctx)
	go s.broadcastLoop(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.auth(s.handleIndex))
	mux.HandleFunc("/ws", s.auth(s.handleWS))
	mux.HandleFunc("/api/kill", s.auth(handleKill))
	mux.HandleFunc("/api/dns", s.auth(s.handleDNS))

	srv := &http.Server{Addr: *addr, Handler: mux}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()

	log.Printf("porthawk ready:  http://%s/?t=%s", *addr, s.token)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
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
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64)).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.resolver.SetEnabled(body.Enabled)
	saveDNSPref(s.cfgDir, body.Enabled)
	w.WriteHeader(http.StatusNoContent)
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
			for i := range conns {
				conns[i].Host = s.resolver.Lookup(conns[i].RAddr)
			}
		}
		conns = s.ghosts.Track(conns)
		if n == 0 {
			continue // tracking done; nobody to send to
		}
		procs, totals := s.hogs.Snapshot()
		snap := Snapshot{
			T: time.Now().UnixMilli(), Me: os.Getuid(),
			DNS: s.resolver.Enabled(), Totals: totals,
			Procs: procs, Conns: conns,
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

func loadDNSPref(dir string) bool {
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return true // default: DNS on
	}
	var c struct {
		DNS *bool `json:"dns"`
	}
	if json.Unmarshal(b, &c) == nil && c.DNS != nil {
		return *c.DNS
	}
	return true
}

func saveDNSPref(dir string, v bool) {
	b, _ := json.Marshal(map[string]bool{"dns": v})
	os.WriteFile(filepath.Join(dir, "config.json"), b, 0o600)
}

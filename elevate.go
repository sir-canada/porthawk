package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Actions that need root, done without porthawk ever being root.
//
// porthawk deliberately runs as you, with four narrow capabilities and no
// way to become root (see the security model in the README). Blocking an
// address in the firewall, or signalling a process you don't own, both
// need more than that. Rather than widen what the server may do, each such
// action is handed to pkexec, which is setuid and asks polkit — so your
// desktop puts up an authentication prompt and a human approves that one
// action. Consequences:
//
//   - Holding the API token is not enough. An attacker with the token, or
//     a page that manages to forge a request, still cannot touch the
//     firewall: the prompt appears on your screen and they cannot answer
//     it. This is the whole reason for using polkit rather than a
//     NOPASSWD sudoers line, which would make the token equal to root.
//   - Nothing is stored. No cached credential, no privileged helper
//     hanging around between actions.
//   - The server never builds a shell command. Arguments are validated
//     (an address must parse as an IP) and passed as an argv array, so
//     there is no string for an injected flag or metacharacter to live in.
//   - The command shape is fixed here. The client chooses *which* action
//     and the target, never the arguments.
//
// If no polkit agent is running — a headless session, say — pkexec fails
// and the response carries the exact command back, so it can be run by
// hand instead. A failure here is never silent.

// elevateTimeout bounds how long an action may sit waiting. It has to be
// generous: the clock starts before the person has seen the prompt, let
// alone typed a password.
const elevateTimeout = 2 * time.Minute

type elevateResult struct {
	OK      bool     `json:"ok"`
	Command []string `json:"cmd"`              // exactly what was run, for the UI to show
	Error   string   `json:"error,omitempty"`  // why it failed
	Output  string   `json:"output,omitempty"` // trimmed stdout+stderr
}

// runElevated executes argv through pkexec and reports the outcome. argv
// must already be validated by the caller.
func runElevated(ctx context.Context, argv []string) elevateResult {
	res := elevateResult{Command: append([]string{"pkexec"}, argv...)}
	if _, err := exec.LookPath("pkexec"); err != nil {
		res.Error = "pkexec is not installed — run the command below yourself"
		return res
	}
	ctx, cancel := context.WithTimeout(ctx, elevateTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "pkexec", argv...)
	// A privileged child inherits nothing it does not need.
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	out, err := cmd.CombinedOutput()
	res.Output = strings.TrimSpace(string(out))
	if len(res.Output) > 2000 {
		res.Output = res.Output[:2000] + "…"
	}
	switch {
	case err == nil:
		res.OK = true
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		res.Error = "timed out waiting for authentication"
	default:
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 126 {
			// pkexec's own code for "not authorised / dismissed".
			res.Error = "authentication was declined or no polkit agent is running"
		} else {
			res.Error = err.Error()
		}
	}
	return res
}

// ---- firewall ----

// handleBlock adds or removes a ufw rule for one address.
//
// Body: {"ip": "1.2.3.4", "undo": false}
//
// Only outbound traffic to the address is touched. That is the direction
// this table is about, and a rule that also blocked inbound would silently
// change how the machine answers the rest of the world.
func (s *server) handleBlock(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		IP   string `json:"ip"`
		Undo bool   `json:"undo"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, req.Body, 256)).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// The address is the only thing the client controls, and it must be an
	// address: no hostnames (which would resolve at rule-application time
	// to something nobody chose), no CIDR, no ufw keywords like "any".
	addr, err := netip.ParseAddr(body.IP)
	if err != nil || addr.IsUnspecified() {
		http.Error(w, "not an IP address", http.StatusBadRequest)
		return
	}
	// A v4-mapped v6 address is a v4 address as far as the firewall is
	// concerned, and ufw does not accept the ::ffff: form.
	addr = addr.Unmap().WithZone("")
	if _, err := exec.LookPath("ufw"); err != nil {
		writeJSON(w, elevateResult{Error: "ufw is not installed"})
		return
	}

	writeJSON(w, runElevated(req.Context(), ufwArgs(addr, body.Undo)))
}

// ufwArgs builds the firewall command. Every element is a literal except
// the address, which is rendered from its parsed form rather than echoed
// back as the client sent it — so even a string that somehow slipped past
// validation could not survive as written.
func ufwArgs(addr netip.Addr, undo bool) []string {
	ip := addr.String()
	if undo {
		// delete matches the rule as written, without the insert position.
		return []string{"ufw", "delete", "deny", "out", "to", ip}
	}
	// "insert 1" puts the rule above any blanket allow that would
	// otherwise match first: ufw is first-match.
	return []string{"ufw", "insert", "1", "deny", "out", "to", ip}
}

// ---- privileged kill ----

// handleKillRoot signals a process that isn't ours. The unprivileged path
// in kill.go stays as it is — it refuses anything not owned by this user,
// and that refusal is worth keeping — so this is a separate, explicitly
// authenticated route rather than a relaxation of that check.
//
// Body: {"pid": 1234, "sig": "term"|"kill"}
func (s *server) handleKillRoot(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		PID int    `json:"pid"`
		Sig string `json:"sig"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, req.Body, 256)).Decode(&body); err != nil || body.PID <= 1 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// PID 1 and below are never targets, and the pid must currently exist:
	// signalling a number that has since been recycled would hit whatever
	// process inherited it.
	if _, err := procUID(body.PID); err != nil {
		http.Error(w, "no such process", http.StatusNotFound)
		return
	}
	sig := "-TERM"
	if body.Sig == "kill" {
		sig = "-KILL"
	}
	writeJSON(w, runElevated(req.Context(), []string{"kill", sig, strconv.Itoa(body.PID)}))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

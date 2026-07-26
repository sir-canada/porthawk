package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"syscall"
)

// handleKill terminates a process. Defense in depth:
//  1. The server never holds CAP_KILL, so the kernel itself refuses
//     signals to processes of other users.
//  2. We still verify /proc/PID ownership matches our own UID and
//     return 403 before ever calling kill(2).
//
// Body: {"pid": 1234, "sig": "term"|"kill"}
func handleKill(w http.ResponseWriter, req *http.Request) {
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

	uid, err := procUID(body.PID)
	if err != nil {
		http.Error(w, "no such process", http.StatusNotFound)
		return
	}
	if uid != uint32(os.Getuid()) {
		http.Error(w, "forbidden: not your process", http.StatusForbidden)
		return
	}

	sig := syscall.SIGTERM
	if body.Sig == "kill" {
		sig = syscall.SIGKILL
	}
	if err := syscall.Kill(body.PID, sig); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// procUID reports the owning uid of a live process. Used both to enforce
// the same-user rule here and, in elevate.go, to confirm a pid still
// exists before asking for authentication to signal it.
func procUID(pid int) (uint32, error) {
	st, err := os.Stat("/proc/" + strconv.Itoa(pid))
	if err != nil {
		return 0, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("cannot read process owner")
	}
	return sys.Uid, nil
}

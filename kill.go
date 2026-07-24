package main

import (
	"encoding/json"
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

	st, err := os.Stat("/proc/" + strconv.Itoa(body.PID))
	if err != nil {
		http.Error(w, "no such process", http.StatusNotFound)
		return
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid != uint32(os.Getuid()) {
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

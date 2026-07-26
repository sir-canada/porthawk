BIN := porthawk
# cap_bpf + cap_perfmon are for the optional per-socket UDP counters
# (udpstats.go). Drop them and everything still runs — UDP rows just read
# zero and the UI says the traffic is unattributed.
CAPS := cap_net_admin,cap_net_raw,cap_dac_read_search,cap_sys_ptrace,cap_bpf,cap_perfmon
PREFIX  := $(HOME)/.local
UNITDIR := $(HOME)/.config/systemd/user

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BIN) .

# Build + grant caps to the binary + run. setcap must be reapplied after
# every rebuild (file caps live on the inode).
dev: build
	sudo setcap "$(CAPS)+eip" ./$(BIN)
	@$(MAKE) --no-print-directory verify-caps BINPATH=./$(BIN)
	./$(BIN)

# setcap can report success and still leave nothing behind: file
# capabilities are an xattr, and a filesystem that does not carry them
# (some NFS/overlay/encrypted setups) drops them silently. Then porthawk
# runs, looks healthy, and quietly cannot attribute any other user's
# socket. Check rather than assume.
verify-caps:
	@getcap "$(BINPATH)" | grep -q cap_sys_ptrace || { \
	  echo ""; \
	  echo "ERROR: capabilities did not stick on $(BINPATH)."; \
	  c=$$(getcap '$(BINPATH)' 2>&1); echo "  getcap says: $${c:-(nothing at all)}"; \
	  echo "  Without cap_dac_read_search + cap_sys_ptrace, sockets belonging to"; \
	  echo "  other users cannot be mapped to a process: those rows render as"; \
	  echo "  \"—\" with no PID and user root."; \
	  echo "  Usual cause: a filesystem that does not support file capabilities"; \
	  echo "  (xattr), e.g. NFS, some overlay or encrypted-home setups."; \
	  echo "  Workaround: install to a path on a local filesystem, e.g."; \
	  echo "    make install PREFIX=/usr/local"; \
	  echo ""; \
	  exit 1; }
	@echo "capabilities ok: $$(getcap '$(BINPATH)')"

# Install + run as a per-user service. One sudo, for setcap only; systemd
# runs it as you, no root at runtime. File caps survive because the unit
# does not set NoNewPrivileges.
install: build
	install -Dm755 $(BIN) $(PREFIX)/bin/$(BIN)
	sudo setcap "$(CAPS)+eip" $(PREFIX)/bin/$(BIN)
	@$(MAKE) --no-print-directory verify-caps BINPATH=$(PREFIX)/bin/$(BIN)
	install -Dm644 porthawk.service $(UNITDIR)/porthawk.service
	systemctl --user daemon-reload
	systemctl --user enable porthawk
	# restart, not `enable --now`: on a reinstall the unit is already
	# active and `--now` would leave the old binary running.
	systemctl --user restart porthawk
	loginctl enable-linger "$$(id -un)" 2>/dev/null || true
	@sleep 1
	@echo "porthawk running as a user service. Open:"
	@echo "  http://127.0.0.1:$$(cat $(HOME)/.config/porthawk/port 2>/dev/null)/?t=$$(cat $(HOME)/.config/porthawk/token 2>/dev/null)"

uninstall:
	-systemctl --user disable --now porthawk
	rm -f $(UNITDIR)/porthawk.service $(PREFIX)/bin/$(BIN)
	systemctl --user daemon-reload

# Rebuild the eBPF object from bpf/udp.c. Only needed when that file
# changes or when targeting a different architecture — the compiled object
# is committed, so a plain `go build` needs no clang and no kernel headers.
bpf:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
	go generate ./...

# Rebuild, reinstall, restart the running service in one step.
restart: install
	systemctl --user restart porthawk

clean:
	rm -f $(BIN)

# Diagnose an install that is running but not attributing sockets.
doctor:
	@echo "binary:   $(PREFIX)/bin/$(BIN)"
	@c=$$(getcap $(PREFIX)/bin/$(BIN) 2>&1); echo "caps:     $${c:-(none — this is the usual problem)}"
	@echo "expected: $(CAPS)=eip"
	@echo "service:  $$(systemctl --user is-active porthawk 2>&1)"
	@echo "port:     $$(cat $(HOME)/.config/porthawk/port 2>/dev/null || echo '(not started yet)')"
	@echo ""
	@echo "attribution warnings in the log (if any):"
	@journalctl --user -u porthawk -n 200 --no-pager 2>/dev/null \
	  | grep -i attribution || echo "  (none)"

.PHONY: build dev install uninstall bpf restart clean verify-caps doctor

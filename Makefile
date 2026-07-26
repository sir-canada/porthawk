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
	./$(BIN)

# Install + run as a per-user service. One sudo, for setcap only; systemd
# runs it as you, no root at runtime. File caps survive because the unit
# does not set NoNewPrivileges.
install: build
	install -Dm755 $(BIN) $(PREFIX)/bin/$(BIN)
	sudo setcap "$(CAPS)+eip" $(PREFIX)/bin/$(BIN)
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

.PHONY: build dev install uninstall bpf restart clean

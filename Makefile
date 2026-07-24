BIN := porthawk
CAPS := cap_net_admin,cap_net_raw,cap_dac_read_search,cap_sys_ptrace
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
	systemctl --user enable --now porthawk
	loginctl enable-linger "$$(id -un)" 2>/dev/null || true
	@sleep 1
	@echo "porthawk running as a user service. Open:"
	@echo "  http://127.0.0.1:7413/?t=$$(cat $(HOME)/.config/porthawk/token 2>/dev/null)"

uninstall:
	-systemctl --user disable --now porthawk
	rm -f $(UNITDIR)/porthawk.service $(PREFIX)/bin/$(BIN)
	systemctl --user daemon-reload

clean:
	rm -f $(BIN)

.PHONY: build dev install uninstall clean

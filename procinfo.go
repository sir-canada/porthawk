package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// appIdentity returns a human-recognizable application/instance label for a
// pid, so the UI can group and name rows by the real app rather than the raw
// process comm. Empty result means "no better name than comm".
//
// Resolution order:
//  1. multi-instance CLI tools keyed by working directory (claude, node, …)
//     — we want per-project instances, so cwd wins over the shared cgroup.
//  2. desktop/app cgroup scope (flatpak, systemd app-*.slice) — collapses all
//     of an app's helper processes (ThinLinc's ssh+vncviewer+pulseaudio, every
//     Brave helper, …) under one name.
//  3. install-path of the executable (/opt/thinlinc/lib/tlclient/ssh →
//     ThinLinc) — catches an app's helper binaries when they were launched
//     outside the app's own cgroup scope (e.g. tlclient started from a
//     terminal, so its ssh inherits the terminal's scope).
//  4. ssh/sshd peers labelled by user@host from the command line.
//  5. "" — caller falls back to comm.
func appIdentity(pid int, comm string) string {
	if pid <= 0 {
		return ""
	}
	proc := "/proc/" + strconv.Itoa(pid)

	exe := exeApp(proc) // "" when the binary isn't inside an app bundle

	// 1. cwd-keyed CLI instances. comm is not always the tool's name — a
	// self-updating CLI runs from a versioned file (claude's exe is
	// ~/.local/share/claude/versions/2.1.217, so comm is "2.1.217") — so
	// the install directory names the tool when comm doesn't.
	if name := cliTool(comm, exe); name != "" {
		if inst := cwdInstance(proc); inst != "" {
			return name + " ⟨" + inst + "⟩"
		}
	}

	// 2. desktop app via cgroup scope.
	if app := cgroupApp(proc); app != "" {
		return app
	}

	// 3. vendor install directory of the executable.
	if exe != "" {
		return exe
	}

	// 4. ssh/sshd by user@host.
	switch comm {
	case "ssh", "sshd":
		if uh := sshUserHost(proc); uh != "" {
			return "ssh " + uh
		}
	}
	return ""
}

// cliTool reports the display name of a multi-instance command-line tool
// worth splitting per working directory, given the process comm and the app
// name derived from its install path. "" means "not one of those tools".
func cliTool(names ...string) string {
	for _, n := range names {
		switch strings.ToLower(n) {
		case "claude", "node", "python", "python3", "deno", "bun", "ruby":
			return n
		}
	}
	return ""
}

// cwdInstance is the basename of the process working directory, or "~" for
// the user's home, used to disambiguate multiple instances of a CLI tool.
func cwdInstance(proc string) string {
	dir, err := os.Readlink(proc + "/cwd")
	if err != nil || dir == "" {
		return ""
	}
	if home, err := os.UserHomeDir(); err == nil {
		if dir == home {
			return "~"
		}
		if rel := strings.TrimPrefix(dir, home+"/"); rel != dir {
			return filepath.Base(rel)
		}
	}
	return filepath.Base(dir)
}

// cgroupApp reads /proc/<pid>/cgroup and maps the leaf scope/service to a
// friendly application name. Handles flatpak (app-flatpak-<id>-*.scope),
// systemd desktop launches (app-<name>@*.service / app-<name>-*.scope) and
// snaps (snap.<name>.*). Returns "" for non-app scopes (login session, plain
// user@.service, init.scope, a terminal's own scope, …).
func cgroupApp(proc string) string {
	b, err := os.ReadFile(proc + "/cgroup")
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(b))
	if i := strings.LastIndexByte(line, '/'); i >= 0 {
		line = line[i+1:] // leaf path segment
	}
	leaf := unescapeSystemd(line)
	// strip systemd unit suffix (.scope/.service/…) and @<instance>, but
	// leave dots inside a reverse-DNS app id intact.
	for _, suf := range []string{".scope", ".service", ".slice", ".mount"} {
		leaf = strings.TrimSuffix(leaf, suf)
	}
	if i := strings.IndexByte(leaf, '@'); i >= 0 {
		leaf = leaf[:i]
	}

	switch {
	case strings.HasPrefix(leaf, "app-flatpak-"):
		id := strings.TrimPrefix(leaf, "app-flatpak-")
		if j := strings.LastIndexByte(id, '-'); j >= 0 && allDigits(id[j+1:]) {
			id = id[:j] // strip trailing instance counter
		}
		return friendly(id)
	case strings.HasPrefix(leaf, "app-"):
		name := strings.TrimPrefix(leaf, "app-")
		// systemd desktop id: <name>-<hash>-<profile>; first token is app.
		if j := strings.IndexByte(name, '-'); j >= 0 {
			name = name[:j]
		}
		return friendly(name)
	case strings.HasPrefix(leaf, "snap."):
		f := strings.Split(leaf, ".")
		if len(f) >= 2 {
			return friendly(f[1])
		}
	}
	return ""
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// exeApp derives an app name from the install directory of the process
// executable. Bundled apps keep all their helper binaries under one vendor
// directory (/opt/thinlinc/lib/tlclient/ssh, /usr/lib/firefox/glxtest, …), so
// that directory identifies the owning app even when the process was started
// outside the app's own cgroup scope.
//
// The bundle directory is whatever it is — no allow-list of applications, so
// an app nobody anticipated still gets named after its own directory. Only
// directories that carry no app identity (multiarch, plain bin/lib trees,
// systemd's own helpers) are rejected, and a binary sitting directly in a
// standard bin directory is rejected too: /usr/bin/ssh is not "an app named
// bin", and comm already says everything there is to say about it.
func exeApp(proc string) string {
	exe, err := os.Readlink(proc + "/exe")
	if err != nil || !strings.HasPrefix(exe, "/") {
		return ""
	}
	return exeAppPath(exe)
}

// exeAppPath is exeApp's path logic, split out so it can be tested without a
// live process.
func exeAppPath(exe string) string {
	// exe of a deleted/replaced binary reads as "<path> (deleted)".
	exe = strings.TrimSuffix(exe, " (deleted)")
	seg := strings.Split(strings.TrimPrefix(exe, "/"), "/")
	if len(seg) < 3 { // need at least <root>/<bundle>/<binary>
		return ""
	}
	binary := seg[len(seg)-1]

	// Find the bundle directory: the first path segment below the install
	// root that isn't itself a generic container directory.
	i := 1 // seg[0] is the install root (opt, usr, snap, home, …)
	if seg[0] == "home" {
		i = 2 // /home/<user>/… — the user name is not an app name
	}
	for i < len(seg)-1 && genericDir(seg[i]) {
		i++
	}
	if i >= len(seg)-1 { // walked to the binary: no bundle dir at all
		return ""
	}
	bundle := seg[i]

	// A bundle whose name is the binary adds nothing over comm.
	if strings.EqualFold(bundle, binary) {
		return ""
	}
	return friendly(bundle)
}

// genericDir reports whether a path segment is a container directory that
// says nothing about which application owns the binary.
func genericDir(s string) bool {
	switch strings.ToLower(s) {
	case "bin", "sbin", "lib", "lib32", "lib64", "libexec", "libx32",
		"share", "local", "usr", "opt", "app", "apps", "current",
		"home", "srv", "var", "run", "tmp", "data", "files", "root",
		"flatpak", "snap", "snapd", "appimage", "resources", "versions",
		"systemd", "systemd-shared", "x86_64-linux-gnu", "aarch64-linux-gnu",
		"i386-linux-gnu", "arm-linux-gnueabihf":
		return true
	}
	// hidden dirs (".local", ".var", …) and version/revision directories
	// (snap's "142", an updater's "2.1.217", "v3.4-beta") — a version is
	// never an app name.
	if strings.HasPrefix(s, ".") || versionDir(s) {
		return true
	}
	return false
}

// versionDir reports whether a path segment is purely a version or revision
// number: digits plus separators, optionally with a leading "v".
func versionDir(s string) bool {
	s = strings.TrimPrefix(strings.ToLower(s), "v")
	if s == "" {
		return false
	}
	digit := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			digit = true
		case c == '.' || c == '-' || c == '_' || c == '+':
		default:
			return false
		}
	}
	return digit
}

// knownApp maps a raw app id to its canonical display name. Purely cosmetic:
// it fixes capitalization and vendor/product mismatches (cendio.tlclient →
// ThinLinc) for ids we happen to recognize. An id that isn't listed is not
// rejected — callers fall back to the id itself.
func knownApp(id string) string {
	id = strings.ToLower(id)
	known := []struct{ sub, name string }{
		{"cendio.tlclient", "ThinLinc"}, {"tlclient", "ThinLinc"},
		{"thinlinc", "ThinLinc"},
		{"brave", "Brave"}, {"firefox", "Firefox"},
		{"chromium", "Chromium"}, {"google-chrome", "Chrome"}, {"chrome", "Chrome"},
		{"code", "VS Code"}, {"discord", "Discord"}, {"spotify", "Spotify"},
		{"slack", "Slack"}, {"telegram", "Telegram"}, {"signal", "Signal"},
		{"steam", "Steam"}, {"thunderbird", "Thunderbird"}, {"zoom", "Zoom"},
	}
	for _, k := range known {
		if strings.Contains(id, k.sub) {
			return k.name
		}
	}
	return ""
}

// friendly maps a raw app id (reverse-DNS or short name) to a display name,
// falling back to the id itself when it isn't a known app.
func friendly(id string) string {
	// Terminal emulators own a cgroup scope, but their children (shells,
	// ssh, CLI tools) inherit it — those are NOT "the terminal", so return
	// "" and let the caller fall back to comm / ssh user@host.
	low := strings.ToLower(id)
	for _, t := range []string{"ghostty", "konsole", "alacritty", "kitty",
		"foot", "wezterm", "xterm", "tilix", "terminator", "gnome-terminal",
		"urxvt", "rxvt", "st-", "yakuake"} {
		if strings.Contains(low, t) {
			return ""
		}
	}
	if k := knownApp(low); k != "" {
		return k
	}
	// Unrecognized: derive a display name from the id itself, keeping its
	// own capitalization (someNewApp stays SomeNewApp).
	id = trimVersionSuffix(id)
	// reverse-DNS ids (com.example.Thing) are named by their last component,
	// but only when that component isn't a version — "webkit2gtk-4.1" must
	// not become "1".
	if i := strings.LastIndexByte(id, '.'); i >= 0 && i < len(id)-1 &&
		!versionDir(id[i+1:]) {
		last := id[i+1:]
		// A last component like "Client", "App" or "Desktop" names a kind
		// of program, not a program: com.thincast.Client would show up as
		// plain "Client", which tells you nothing and collides with every
		// other vendor's client. The segment before it is the part that
		// identifies anything, so use that instead.
		if genericAppWord(last) {
			if v := vendorSegment(id[:i]); v != "" {
				return titleWord(v)
			}
		}
		id = last
	}
	return titleWord(id)
}

// vendorSegment picks the meaningful part of a reverse-DNS prefix:
// "com.thincast" -> "thincast", "io.github.someone" -> "someone". Returns
// "" when nothing but boilerplate is left.
func vendorSegment(prefix string) string {
	parts := strings.Split(prefix, ".")
	for i := len(parts) - 1; i >= 0; i-- {
		p := strings.TrimSpace(parts[i])
		if p == "" || versionDir(p) || genericAppWord(p) {
			continue
		}
		switch strings.ToLower(p) {
		// Registry boilerplate: every id starts with one of these and none
		// of them says whose program this is.
		case "com", "org", "net", "io", "dev", "me", "co", "eu", "de", "fr",
			"uk", "us", "xyz", "page", "site", "cloud", "github", "gitlab",
			"sourceforge", "freedesktop", "gnome", "kde":
			continue
		}
		return p
	}
	return ""
}

// genericAppWord reports whether a name describes a category of program
// rather than naming one. These turn up as the last component of app ids
// ("com.vendor.Client") and as binary names inside a vendor's install
// directory ("/opt/vendor/bin/client"), where on their own they are
// useless in a process list.
func genericAppWord(s string) bool {
	switch strings.ToLower(s) {
	case "client", "server", "app", "application", "desktop", "gui", "ui",
		"main", "launcher", "loader", "starter", "start", "run", "runner",
		"exec", "wrapper", "helper", "agent", "daemon", "service",
		"viewer", "browser", "player", "manager", "monitor", "tool",
		"bin", "binary", "program", "electron", "shell", "frontend":
		return true
	}
	return false
}

func titleWord(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// trimVersionSuffix drops trailing version tokens from an app id, so
// "webkit2gtk-4.1" reads as "webkit2gtk" and "myapp_2.0" as "myapp".
func trimVersionSuffix(id string) string {
	for {
		i := strings.LastIndexAny(id, "-_")
		if i <= 0 || !versionDir(id[i+1:]) {
			return id
		}
		id = id[:i]
	}
}

// sshUserHost scans the ssh command line for a user@host argument.
func sshUserHost(proc string) string {
	b, err := os.ReadFile(proc + "/cmdline")
	if err != nil {
		return ""
	}
	for _, arg := range strings.Split(string(b), "\x00") {
		if strings.HasPrefix(arg, "-") || arg == "" {
			continue
		}
		at := strings.IndexByte(arg, '@')
		if at > 0 && at < len(arg)-1 &&
			!strings.ContainsAny(arg, " /\"'") {
			return arg
		}
	}
	return ""
}

// unescapeSystemd decodes systemd cgroup \xNN hex escapes (e.g. \x2d -> '-').
func unescapeSystemd(s string) string {
	if !strings.Contains(s, `\x`) {
		return s
	}
	var out strings.Builder
	for i := 0; i < len(s); {
		if i+3 < len(s) && s[i] == '\\' && s[i+1] == 'x' {
			if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				out.WriteByte(byte(v))
				i += 4
				continue
			}
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}

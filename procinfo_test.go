package main

import "testing"

func TestExeAppPath(t *testing.T) {
	cases := []struct{ exe, want string }{
		// Bundled apps: the bundle directory names the app, whatever it is.
		{"/opt/thinlinc/lib/tlclient/ssh", "ThinLinc"},
		{"/opt/someNewApp/3.2.1/bin/helper", "SomeNewApp"}, // unknown app, own casing kept
		{"/var/lib/flatpak/app/com.brave.Browser/x86_64/stable/ab/files/brave/brave", "Brave"},
		{"/home/x/.local/share/claude/versions/2.1.217", "Claude"},
		{"/home/x/.local/share/JetBrains/Toolbox/bin/jetbrains-toolbox", "JetBrains"},
		{"/usr/lib/x86_64-linux-gnu/webkit2gtk-4.1/WebKitNetworkProcess", "Webkit2gtk"},

		// Nothing an app name can be derived from: caller falls back to comm.
		{"/usr/bin/ssh", ""},
		{"/usr/lib/systemd/systemd-resolved", ""},
		{"/usr/lib/firefox/firefox", ""}, // bundle == binary, adds nothing
		{"/snap/spotify/142/usr/bin/spotify", ""},
		{"/usr/lib/ghostty/ghostty", ""}, // terminal: children aren't "the terminal"
		{"relative/path", ""},
	}
	for _, c := range cases {
		if got := exeAppPath(c.exe); got != c.want {
			t.Errorf("exeAppPath(%q) = %q, want %q", c.exe, got, c.want)
		}
	}
	// A replaced binary still resolves.
	if got := exeAppPath("/opt/thinlinc/lib/tlclient/ssh (deleted)"); got != "ThinLinc" {
		t.Errorf("deleted exe = %q, want ThinLinc", got)
	}
}

func TestVersionDir(t *testing.T) {
	for _, s := range []string{"142", "2.1.217", "v3.4", "4.1", "1_2"} {
		if !versionDir(s) {
			t.Errorf("versionDir(%q) = false, want true", s)
		}
	}
	// Deliberately strict: anything with letters in it may be a real name,
	// so a pre-release tag like "v3.4-beta1" is left alone rather than
	// risking a directory named e.g. "gtk4" being treated as a version.
	for _, s := range []string{"thinlinc", "webkit2gtk", "", "beta", "v", "v3.4-beta1"} {
		if versionDir(s) {
			t.Errorf("versionDir(%q) = true, want false", s)
		}
	}
}

func TestFriendly(t *testing.T) {
	cases := []struct{ id, want string }{
		{"cendio.tlclient", "ThinLinc"},
		{"org.gnome.Fractal", "Fractal"}, // unknown reverse-DNS id
		{"webkit2gtk-4.1", "Webkit2gtk"}, // version suffix is not the name
		{"someNewApp", "SomeNewApp"},
		{"app-ghostty-surface", ""}, // terminal
		{"", ""},
		// A trailing word that names a category of program, not a program:
		// the vendor before it is the only part that identifies anything.
		{"com.thincast.Client", "Thincast"},
		{"com.vendor.Desktop", "Vendor"},
		{"io.github.someone.App", "Someone"}, // forge namespaces are boilerplate
		{"org.remmina.Remmina", "Remmina"},   // real name, left alone
		{"com.client", "Client"},             // nothing better to fall back to
	}
	for _, c := range cases {
		if got := friendly(c.id); got != c.want {
			t.Errorf("friendly(%q) = %q, want %q", c.id, got, c.want)
		}
	}
}

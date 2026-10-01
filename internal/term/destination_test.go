package term

import (
	"bytes"
	"io"
	"os"
	"testing"
)

func TestEnabledForPolicy(t *testing.T) {
	for _, tc := range []struct {
		name     string
		terminal bool
		env      map[string]string
		want     bool
	}{
		{name: "terminal", terminal: true, want: true},
		{name: "redirected"},
		{name: "auto terminal", terminal: true, env: map[string]string{"RUA_COLOR": "auto"}, want: true},
		{name: "auto redirected", env: map[string]string{"RUA_COLOR": "auto"}},
		{name: "dumb terminal", terminal: true, env: map[string]string{"TERM": "dumb"}},
		{name: "always overrides all", env: map[string]string{"RUA_COLOR": "always", "NO_COLOR": "", "CLICOLOR": "0", "TERM": "dumb"}, want: true},
		{name: "never overrides force", terminal: true, env: map[string]string{"RUA_COLOR": "never", "CLICOLOR_FORCE": "1"}},
		{name: "empty no color overrides force", terminal: true, env: map[string]string{"NO_COLOR": "", "CLICOLOR_FORCE": "1"}},
		{name: "no color with auto", terminal: true, env: map[string]string{"RUA_COLOR": "auto", "NO_COLOR": "1"}},
		{name: "force redirected", env: map[string]string{"CLICOLOR_FORCE": "1"}, want: true},
		{name: "force with auto overrides clicolor", env: map[string]string{"RUA_COLOR": "auto", "CLICOLOR_FORCE": "1", "CLICOLOR": "0", "TERM": "dumb"}, want: true},
		{name: "clicolor disables", terminal: true, env: map[string]string{"CLICOLOR": "0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cleanColorEnv(t)
			for key, value := range tc.env {
				t.Setenv(key, value)
			}
			if got := enabledFor(io.Discard, func(io.Writer) bool { return tc.terminal }); got != tc.want {
				t.Fatalf("enabled = %t, want %t", got, tc.want)
			}
		})
	}
}

func cleanColorEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{"RUA_COLOR", "NO_COLOR", "CLICOLOR_FORCE", "CLICOLOR", "TERM"} {
		// Setenv registers restoration before removing the variable entirely.
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEnabledForDestinations(t *testing.T) {
	cleanColorEnv(t)
	f, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	for _, dst := range []io.Writer{&bytes.Buffer{}, io.Discard, f, w} {
		if EnabledFor(dst) {
			t.Errorf("color enabled for nonterminal %T", dst)
		}
	}
	if !computeEnabled() {
		t.Fatal("legacy color default changed")
	}
	t.Setenv("RUA_COLOR", "always")
	if !EnabledFor(&bytes.Buffer{}) {
		t.Fatal("explicit color override ignored")
	}
}

func TestEnabledForTerminal(t *testing.T) {
	cleanColorEnv(t)
	f, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("pseudoterminal unavailable: %v", err)
	}
	defer f.Close()
	if !EnabledFor(f) {
		t.Fatal("terminal was not detected")
	}
	t.Setenv("TERM", "dumb")
	if EnabledFor(f) {
		t.Fatal("color enabled for dumb terminal")
	}
}

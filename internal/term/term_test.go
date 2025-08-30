package term

import (
	"os"
	"strings"
	"testing"
)

// recomputeEnabled mirrors the package init logic to allow testing env-driven behavior.
func recomputeEnabled() bool {
	if v := strings.ToLower(os.Getenv("RUA_COLOR")); v != "" {
		switch v {
		case "always":
			return true
		case "never":
			return false
		}
		// auto -> fall through
	}
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	if os.Getenv("CLICOLOR_FORCE") == "1" {
		return true
	}
	if os.Getenv("CLICOLOR") == "0" {
		return false
	}
	return true
}

func TestEnabledEnv(t *testing.T) {
	t.Setenv("RUA_COLOR", "never")
	enabled = recomputeEnabled()
	if Enabled() {
		t.Fatalf("expected disabled with RUA_COLOR=never")
	}
	t.Setenv("RUA_COLOR", "always")
	enabled = recomputeEnabled()
	if !Enabled() {
		t.Fatalf("expected enabled with RUA_COLOR=always")
	}
	t.Setenv("RUA_COLOR", "auto")
	t.Setenv("NO_COLOR", "1")
	enabled = recomputeEnabled()
	if Enabled() {
		t.Fatalf("expected disabled with NO_COLOR set")
	}
}

func TestWrap(t *testing.T) {
	// force on
	t.Setenv("RUA_COLOR", "always")
	enabled = recomputeEnabled()
	s := Bold("x")
	if !strings.Contains(s, "\x1b[") {
		t.Fatalf("expected ANSI codes present: %q", s)
	}
	// force off
	t.Setenv("RUA_COLOR", "never")
	enabled = recomputeEnabled()
	s2 := Red("y")
	if s2 != "y" {
		t.Fatalf("expected no ANSI when disabled: %q", s2)
	}
}

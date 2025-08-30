package term

import (
	"os"
	"strings"
	"testing"
)

// recomputeEnabled mirrors the package init logic to allow testing env-driven behavior.
func TestEnabledEnv(t *testing.T) {
	t.Setenv("RUA_COLOR", "never")
	RecomputeForTests()
	if Enabled() {
		t.Fatalf("expected disabled with RUA_COLOR=never")
	}
	t.Setenv("RUA_COLOR", "always")
	RecomputeForTests()
	if !Enabled() {
		t.Fatalf("expected enabled with RUA_COLOR=always")
	}
	t.Setenv("RUA_COLOR", "auto")
	t.Setenv("NO_COLOR", "1")
	RecomputeForTests()
	if Enabled() {
		t.Fatalf("expected disabled with NO_COLOR set")
	}
	// CLICOLOR_FORCE forces enabled
	_ = os.Unsetenv("NO_COLOR")
	t.Setenv("CLICOLOR_FORCE", "1")
	RecomputeForTests()
	if !Enabled() {
		t.Fatalf("expected enabled with CLICOLOR_FORCE=1")
	}
	// CLICOLOR=0 disables
	t.Setenv("CLICOLOR_FORCE", "")
	t.Setenv("CLICOLOR", "0")
	RecomputeForTests()
	if Enabled() {
		t.Fatalf("expected disabled with CLICOLOR=0")
	}
}

func TestWrap(t *testing.T) {
	// force on
	t.Setenv("RUA_COLOR", "always")
	RecomputeForTests()
	s := Bold("x")
	if !strings.Contains(s, "\x1b[") {
		t.Fatalf("expected ANSI codes present: %q", s)
	}
	// force off
	t.Setenv("RUA_COLOR", "never")
	RecomputeForTests()
	s2 := Red("y")
	if s2 != "y" {
		t.Fatalf("expected no ANSI when disabled: %q", s2)
	}
}

func TestAllColors(t *testing.T) {
	t.Setenv("RUA_COLOR", "always")
	RecomputeForTests()
	_ = Bold("x")
	_ = Red("x")
	_ = Green("x")
	_ = Yellow("x")
	_ = Blue("x")
	_ = Magenta("x")
	_ = Cyan("x")
}

func TestWrapEmptyNoCodes(t *testing.T) {
	t.Setenv("RUA_COLOR", "always")
	RecomputeForTests()
	if got := Bold(""); got != "" {
		t.Fatalf("expected empty unchanged, got %q", got)
	}
}

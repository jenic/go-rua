package term

import (
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// colorOverride returns an explicit environment preference, if any.
func colorOverride() (bool, bool) {
	if v := strings.ToLower(os.Getenv("RUA_COLOR")); v != "" {
		switch v {
		case "always":
			return true, true
		case "never":
			return false, true
		}
		// auto -> fall through
	}
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false, true
	}
	if os.Getenv("CLICOLOR_FORCE") == "1" {
		return true, true
	}
	if os.Getenv("CLICOLOR") == "0" {
		return false, true
	}
	return false, false
}

// computeEnabled retains the legacy default for existing color helpers.
func computeEnabled() bool {
	if enabled, overridden := colorOverride(); overridden {
		return enabled
	}
	return true
}

// EnabledFor honors color overrides and otherwise enables color only for a
// terminal destination. Unknown writers are treated as nonterminals.
func EnabledFor(w io.Writer) bool {
	return enabledFor(w, isTerminal)
}

func enabledFor(w io.Writer, terminal func(io.Writer) bool) bool {
	if enabled, overridden := colorOverride(); overridden {
		return enabled
	}
	return os.Getenv("TERM") != "dumb" && terminal(w)
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(interface{ Fd() uintptr })
	if !ok {
		return false
	}
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

var enabled = computeEnabled()

func Enabled() bool { return enabled }

// Recompute recalculates color enablement from the current environment.
func Recompute() { enabled = computeEnabled() }

// RecomputeForTests retains the existing test helper API.
func RecomputeForTests() { Recompute() }

func wrap(code, s string) string {
	if !enabled || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func Bold(s string) string    { return wrap("1", s) }
func Red(s string) string     { return wrap("31", s) }
func Green(s string) string   { return wrap("32", s) }
func Yellow(s string) string  { return wrap("33", s) }
func Blue(s string) string    { return wrap("34", s) }
func Magenta(s string) string { return wrap("35", s) }
func Cyan(s string) string    { return wrap("36", s) }

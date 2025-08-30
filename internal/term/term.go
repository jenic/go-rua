package term

import (
	"os"
	"strings"
)

// computeEnabled contains the logic for determining color enablement.
func computeEnabled() bool {
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
	// default: enabled
	return true
}

var enabled = computeEnabled()

func Enabled() bool { return enabled }

// RecomputeForTests recalculates enablement using current env (testing helper).
func RecomputeForTests() { enabled = computeEnabled() }

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

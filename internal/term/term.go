package term

import (
	"os"
	"strings"
)

// Enabled reports whether colored output should be used.
// Rules:
// - RUA_COLOR=always|never|auto overrides.
// - NO_COLOR disables when set to any value.
// - CLICOLOR=0 disables; CLICOLOR_FORCE=1 forces.
// - Defaults to auto (enabled when stdout is a TTY is ideal, but we keep it on by default here).
var enabled = func() bool {
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
}()

func Enabled() bool { return enabled }

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

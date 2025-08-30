package pacman

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type ForeignPkg struct {
	Name    string
	Version string
}

// GetForeignPackages returns packages not in the sync db (AUR/foreign)
func GetForeignPackages() ([]ForeignPkg, error) {
	cmd := exec.Command("pacman", "-Q", "--foreign", "--color=never")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("pacman -Q --foreign failed: %w", err)
	}
	res := []ForeignPkg{}
	s := bufio.NewScanner(strings.NewReader(string(out)))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			res = append(res, ForeignPkg{Name: parts[0], Version: parts[1]})
		}
	}
	return res, nil
}

// Vercmp compares versions using pacman's vercmp; returns -1,0,1
func Vercmp(a, b string) (int, error) {
	cmd := exec.Command("vercmp", a, b)
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("vercmp failed: %w", err)
	}
	val := strings.TrimSpace(string(out))
	switch val {
	case "-1":
		return -1, nil
	case "0":
		return 0, nil
	case "1":
		return 1, nil
	default:
		return 0, fmt.Errorf("unexpected vercmp output: %q", val)
	}
}

// StripDepName extracts the package/provide name from a dependency expression
// Examples:
//
//	"foo>=1.2" -> "foo"
//	"bar=2"    -> "bar"
//	"baz<3"    -> "baz"
//	"libabc.so" -> "libabc.so"
func StripDepName(dep string) string {
	s := strings.TrimSpace(dep)
	// split on any version relation operator
	for _, op := range []string{">=", "<=", "=", ">", "<"} {
		if i := strings.Index(s, op); i >= 0 {
			return strings.TrimSpace(s[:i])
		}
	}
	return s
}

// CheckMissing returns which of the given dependency names are not satisfied on the system.
// It shells out to `pacman -T`, which prints unsatisfied deps one per line.
func CheckMissing(names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	args := append([]string{"-T"}, names...)
	cmd := exec.Command("pacman", args...)
	out, err := cmd.Output()
	if err != nil {
		// pacman -T returns non-zero only on fatal error; unsatisfied are printed to stdout.
		// If we get an error here, propagate it since stdout is unreliable.
		return nil, fmt.Errorf("pacman -T failed: %w", err)
	}
	var missing []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		if t != "" {
			missing = append(missing, t)
		}
	}
	return missing, nil
}

// IsRepoPackage checks if a given package name exists in sync db (repos), via `pacman -Si`.
func IsRepoPackage(name string) (bool, error) {
	cmd := exec.Command("pacman", "-Si", name)
	if err := cmd.Run(); err != nil {
		// non-zero -> not found in repos or pacman error
		if _, ok := err.(*exec.ExitError); ok {
			return false, nil
		}
		return false, fmt.Errorf("pacman -Si failed: %w", err)
	}
	return true, nil
}

// InstallRepoDeps runs `sudo pacman -S --needed ...` for the given names.
func InstallRepoDeps(names []string) error {
	if len(names) == 0 {
		return nil
	}
	args := append([]string{"pacman", "-S", "--needed"}, names...)
	cmd := exec.Command("sudo", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// InstallLocal installs local package files using `sudo pacman -U --needed` interactively.
func InstallLocal(files []string) error {
	if len(files) == 0 {
		return nil
	}
	args := append([]string{"pacman", "-U", "--needed"}, files...)
	cmd := exec.Command("sudo", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

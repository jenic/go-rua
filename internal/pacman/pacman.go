package pacman

import (
	"bufio"
	"fmt"
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

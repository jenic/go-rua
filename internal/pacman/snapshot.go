package pacman

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
)

type Snapshot struct {
	Versions map[string]string
	Files    map[string]map[string]bool
	Owners   map[string][]string
}

var queryOutput = func(args ...string) ([]byte, error) { return exec.Command("pacman", args...).Output() }

// InstalledSnapshot uses the local package database, never a network query.
func InstalledSnapshot() (Snapshot, error) {
	s := Snapshot{Versions: map[string]string{}, Files: map[string]map[string]bool{}, Owners: map[string][]string{}}
	out, err := queryOutput("-Q", "--color=never")
	if err != nil {
		return s, fmt.Errorf("read installed versions: %w", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return s, fmt.Errorf("malformed installed version record")
		}
		s.Versions[fields[0]] = fields[1]
	}
	if len(s.Versions) == 0 {
		return s, nil
	}
	out, err = queryOutput("-Ql", "--color=never")
	if err != nil {
		return s, fmt.Errorf("read installed file ownership: %w", err)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		name, path, ok := strings.Cut(scanner.Text(), " ")
		if !ok || !strings.HasPrefix(path, "/") || s.Versions[name] == "" {
			return s, fmt.Errorf("malformed installed ownership record")
		}
		path = strings.TrimPrefix(path, "/")
		if path == "" {
			continue
		}
		if s.Files[name] == nil {
			s.Files[name] = map[string]bool{}
		}
		s.Files[name][path] = true
		s.Owners[strings.TrimSuffix(path, "/")] = append(s.Owners[strings.TrimSuffix(path, "/")], name)
	}
	return s, scanner.Err()
}

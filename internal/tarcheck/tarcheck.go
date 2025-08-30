package tarcheck

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"go-rua/internal/sandbox"
)

type entry struct {
	Perm  string // first field from `tar -tvf`, e.g. -rwsr-xr-x
	Path  string
	IsDir bool
}

// TarCheck analyzes a .pkg.tar* archive and provides an interactive review.
func TarCheck(archivePath string) error {
	entries, install, err := listArchive(archivePath)
	if err != nil {
		return err
	}

	all := []string{}
	execs := []string{}
	suids := []string{}
	for _, e := range entries {
		if !e.IsDir && !strings.HasPrefix(e.Path, ".") {
			all = append(all, e.Path)
		}
		if !e.IsDir && isExec(e.Perm) {
			execs = append(execs, e.Path)
		}
		if isSUID(e.Perm) {
			suids = append(suids, e.Path)
		}
	}

	// UI loop
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Package %s has %d files; %d exec; %d SUID.\n", filepath.Base(archivePath), len(all), len(execs), len(suids))
	for {
		if len(suids) == 0 {
			fmt.Println("No SUID files detected.")
		}
		fmt.Print("[E]=exec files, [L]=all files, [F]=not on FS, ")
		fmt.Print("[T]=shell, ")
		if install != "" {
			fmt.Print("[I]=show INSTALL, ")
		}
		if len(suids) > 0 {
			fmt.Print("[S]=SUID files, ")
		}
		fmt.Print("[O]=ok proceed: ")
		line, _ := reader.ReadString('\n')
		line = strings.ToLower(strings.TrimSpace(line))
		switch line {
		case "e":
			for _, p := range execs {
				fmt.Println(p)
			}
		case "l":
			for _, p := range all {
				fmt.Println(p)
			}
		case "f":
			for _, p := range all {
				if _, err := os.Stat("/" + p); err != nil {
					fmt.Println(p)
				}
			}
		case "s":
			for _, p := range suids {
				fmt.Println(p)
			}
		case "i":
			if install != "" {
				fmt.Println(install)
			}
		case "t":
			// sandboxed shell with RO access to archive dir
			sh := os.Getenv("SHELL")
			if sh == "" {
				sh = "/bin/bash"
			}
			cfg := sandbox.Config{
				RO:  []string{"/etc", filepath.Dir(archivePath)},
				ROX: []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"},
			}
			fmt.Println("Exit the shell with Ctrl-D...")
			_ = sandbox.Run(cfg, []string{sh})
		case "o":
			return nil
		case "q":
			os.Exit(1)
		}
	}
}

func listArchive(path string) ([]entry, string, error) {
	// Use tar -tvf to list with modes via sandbox (RO on archive dir)
	cfg := sandbox.Config{RO: []string{"/etc", filepath.Dir(path)}, ROX: []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"}}
	out, _, err := sandbox.RunCapture(cfg, []string{"tar", "-tvf", path})
	if err != nil {
		return nil, "", fmt.Errorf("tar -tvf failed: %v\n%s", err, out)
	}
	lines := strings.Split(out, "\n")
	entries := []entry{}
	installContent := ""
	re := regexp.MustCompile(`^([drwxstST-]{10})\s+[^\s]+\s+\d+\s+[^\s]+\s+[^\s]+\s+(.+)$`)
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		// GNU tar starts with perms; last field is path (may contain spaces). Do a best-effort parse.
		m := re.FindStringSubmatch(l)
		if len(m) == 3 {
			perm := m[1]
			path := m[2]
			entries = append(entries, entry{Perm: perm, Path: path, IsDir: perm[0] == 'd'})
		}
	}

	// Try to extract .INSTALL if present
	hasInstall := false
	for _, e := range entries {
		if e.Path == ".INSTALL" {
			hasInstall = true
			break
		}
	}
	if hasInstall {
		out2, _, err := sandbox.RunCapture(cfg, []string{"tar", "-xOf", path, ".INSTALL"})
		if err == nil {
			installContent = out2
		}
	}
	return entries, installContent, nil
}

func isExec(perm string) bool {
	if len(perm) < 10 {
		return false
	}
	// positions 3,6,9 correspond to x bits; also s/t imply executable
	// Correct positions are 4,7,10 when including file type at index 0
	for _, i := range []int{4, 7, 10} {
		c := perm[i-1]
		if c == 'x' || c == 's' || c == 't' {
			return true
		}
	}
	return false
}

func isSUID(perm string) bool {
	if len(perm) < 10 {
		return false
	}
	// lower or upper 's' in user or group exec spots imply setuid/setgid
	// Correct positions are 4 (user exec) and 7 (group exec)
	for _, i := range []int{4, 7} {
		c := perm[i-1]
		if c == 's' || c == 'S' {
			return true
		}
	}
	return false
}

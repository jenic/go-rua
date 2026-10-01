package tarcheck

import (
	"archive/tar"
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"go-rua/internal/review"
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
		if !e.IsDir && !packageMetadata(e.Path) {
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
	reader := bufio.NewReader(getInput())
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
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("archive review cancelled: %w", err)
		}
		line = strings.ToLower(strings.TrimSpace(line))
		switch line {
		case "e":
			for _, p := range execs {
				fmt.Println(review.Safe(p))
			}
		case "l":
			for _, p := range all {
				fmt.Println(review.Safe(p))
			}
		case "f":
			for _, p := range all {
				if _, err := os.Lstat("/" + p); os.IsNotExist(err) {
					fmt.Println(review.Safe(p))
				}
			}
		case "s":
			for _, p := range suids {
				fmt.Println(review.Safe(p))
			}
		case "i":
			if install != "" {
				fmt.Println(review.Safe(install))
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
			return fmt.Errorf("archive review cancelled")
		}
	}
}

var inputOverride io.Reader

// getInput returns stdin unless overridden by tests.
func getInput() io.Reader {
	if inputOverride != nil {
		return inputOverride
	}
	return os.Stdin
}

// SetInputForTests allows tests to feed scripted input to TarCheck.
func SetInputForTests(r io.Reader) { inputOverride = r }

func listArchive(path string) ([]entry, string, error) {
	manifest, report, err := Inspect(path)
	if err != nil {
		return nil, "", err
	}
	report.Print(os.Stdout)
	if report.Has(review.Block) {
		return nil, "", fmt.Errorf("archive inspection blocked")
	}
	var entries []entry
	for _, f := range manifest.Files {
		perm := []byte("----------")
		if f.Type == tar.TypeDir {
			perm[0] = 'd'
		}
		if f.Type == tar.TypeSymlink {
			perm[0] = 'l'
		}
		for i, c := range []byte("rwxrwxrwx") {
			if f.Mode&(1<<(8-i)) != 0 {
				perm[i+1] = c
			}
		}
		if f.Mode&04000 != 0 {
			perm[3] = 'S'
			if f.Mode&0100 != 0 {
				perm[3] = 's'
			}
		}
		if f.Mode&02000 != 0 {
			perm[6] = 'S'
			if f.Mode&0010 != 0 {
				perm[6] = 's'
			}
		}
		entries = append(entries, entry{Perm: string(perm), Path: f.Path, IsDir: f.Type == tar.TypeDir})
	}
	return entries, manifest.Install, nil
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

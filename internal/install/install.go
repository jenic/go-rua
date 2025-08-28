package install

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"go-rua/internal/aur"
	"go-rua/internal/build"
	"go-rua/internal/paths"
	"go-rua/internal/shellutil"
	"go-rua/internal/tarcheck"
)

type Options struct {
	Offline bool
	Force   bool
}

// Install clones AUR repos for packages, offers a simple review shell, builds and stages artifacts
func Install(pkgs []string, p paths.Paths, opt Options) error {
	if len(pkgs) == 0 {
		return errors.New("no packages provided")
	}

	infos, err := aur.Info(pkgs)
	if err != nil {
		return err
	}
	if len(infos) == 0 {
		return fmt.Errorf("no AUR packages found for: %v", pkgs)
	}

	for _, inf := range infos {
		pkgbase := inf.PackageBase
		if pkgbase == "" {
			pkgbase = inf.Name
		}
		reviewDir := p.ReviewDir(pkgbase)

		if _, err := os.Stat(filepath.Join(reviewDir, ".git")); err != nil {
			// clone fresh
			repo := fmt.Sprintf("https://aur.archlinux.org/%s.git", pkgbase)
			if err := run("git", "clone", repo, reviewDir); err != nil {
				return fmt.Errorf("git clone failed: %w", err)
			}
		} else {
			// fetch updates
			if err := runC(reviewDir, "git", "fetch", "--all", "-p"); err != nil {
				return err
			}
			// reset to origin/master (keeps local edits separate; a more advanced merge flow can be added later)
			_ = runC(reviewDir, "git", "checkout", "master")
			_ = runC(reviewDir, "git", "reset", "--hard", "origin/master")
		}

		// Simple review prompt
		fmt.Printf("\nReviewing %s at %s\n", pkgbase, reviewDir)
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("[S]=shellcheck, [N]=namcap, [T]=shell, [D]=git diff, [O]=ok continue: ")
			text, _ := reader.ReadString('\n')
			text = strings.ToLower(strings.TrimSpace(text))
			switch text {
			case "s":
				_ = shellcheck(reviewDir)
			case "n":
				_ = namcap(reviewDir)
			case "t":
				// open sandboxed shell for user edits
				fmt.Println("Exit the shell with Ctrl-D...")
				_ = build.RunShell(reviewDir)
			case "d":
				_ = runC(reviewDir, "git", "--no-pager", "diff")
			case "o":
				goto BUILD
			}
		}

	BUILD:
		buildDir := p.BuildDir(pkgbase)
		// clean build dir
		_ = os.RemoveAll(buildDir)
		if err := os.MkdirAll(buildDir, 0o755); err != nil {
			return err
		}
		// copy review -> build
		if err := build.CopyTree(reviewDir, buildDir); err != nil {
			return err
		}
		_ = os.RemoveAll(filepath.Join(buildDir, ".git"))

		// build
		if err := build.BuildDirectory(buildDir, p, opt.Offline, opt.Force); err != nil {
			return err
		}

		// find built tars
		files, _ := os.ReadDir(buildDir)
		var tars []string
		for _, f := range files {
			name := f.Name()
			if strings.HasSuffix(name, ".pkg.tar") || strings.HasSuffix(name, ".pkg.tar.xz") ||
				strings.HasSuffix(name, ".pkg.tar.gz") || strings.HasSuffix(name, ".pkg.tar.zst") {
				tars = append(tars, filepath.Join(buildDir, name))
			}
		}
		// tarcheck interactively for each
		for _, t := range tars {
			if err := tarcheck.TarCheck(t); err != nil {
				return err
			}
		}

		// move to checked_tars
		dstDir := p.CheckedTarsDir(pkgbase)
		for _, t := range tars {
			base := filepath.Base(t)
			if err := moveCrossDevice(t, filepath.Join(dstDir, base)); err != nil {
				return err
			}
			// move signature if present
			sigSrc := t + ".sig"
			if _, err := os.Stat(sigSrc); err == nil {
				_ = moveCrossDevice(sigSrc, filepath.Join(dstDir, base+".sig"))
			}
		}
		fmt.Printf("Artifacts staged at %s\n", dstDir)
	}
	return nil
}

func moveCrossDevice(src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		// fallback copy+remove
		in, err2 := os.Open(src)
		if err2 != nil {
			return err
		}
		defer in.Close()
		out, err3 := os.Create(dst)
		if err3 != nil {
			return err3
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		out.Close()
		return os.Remove(src)
	}
	return nil
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func runC(dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// wrappers
func shellcheck(dir string) error {
	return shellutil.Shellcheck(filepath.Join(dir, "PKGBUILD"), paths.Paths{})
}
func namcap(dir string) error { return shellutil.Namcap(filepath.Join(dir, "PKGBUILD"), paths.Paths{}) }

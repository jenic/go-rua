package install

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"go-rua/internal/aur"
	"go-rua/internal/build"
	"go-rua/internal/pacman"
	"go-rua/internal/paths"
	"go-rua/internal/shellutil"
	"go-rua/internal/tarcheck"
)

type Options struct {
	Offline bool
	Force   bool
	// NonInteractive skips the interactive review shell/diff steps
	NonInteractive bool
	// InstallBuilt installs built artifacts with pacman -U after staging
	InstallBuilt bool
	// DisableSeccomp disables applying seccomp denylist during build
	DisableSeccomp bool
	// AsDeps installs built packages as dependencies
	AsDeps bool
}

// Install clones AUR repos for packages, offers a simple review shell, builds and stages artifacts
func Install(pkgs []string, p paths.Paths, opt Options) error {
	if len(pkgs) == 0 {
		return errors.New("no packages provided")
	}
	// Build dependency plan
	plan, err := BuildPlan(pkgs)
	if err != nil {
		return err
	}
	if len(plan.BuildOrder) == 0 {
		return fmt.Errorf("no AUR packages to build for: %v", pkgs)
	}
	// Resolve AUR info for the closure to map name->pkgbase
	infos, err := aur.Info(plan.BuildOrder)
	if err != nil {
		return err
	}
	nameToBase := map[string]string{}
	for _, inf := range infos {
		base := inf.PackageBase
		if base == "" {
			base = inf.Name
		}
		nameToBase[inf.Name] = base
	}
	// Collect unique pkgbase entries with max depth across split packages
	type entry struct {
		Base  string
		Depth int
	}
	baseDepth := map[string]int{}
	for _, name := range plan.BuildOrder {
		base := nameToBase[name]
		if base == "" {
			base = name
		}
		d := plan.Depths[name]
		if cur, ok := baseDepth[base]; !ok || d > cur {
			baseDepth[base] = d
		}
	}
	// Prepare sorted entries by depth desc, then alpha
	entries := make([]entry, 0, len(baseDepth))
	for b, d := range baseDepth {
		entries = append(entries, entry{b, d})
	}
	// sort
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Depth != entries[j].Depth {
			return entries[i].Depth > entries[j].Depth
		}
		return entries[i].Base < entries[j].Base
	})
	// Process group by depth: review, build, tarcheck, stage; then install per group
	i := 0
	for i < len(entries) {
		depth := entries[i].Depth
		j := i
		for j < len(entries) && entries[j].Depth == depth {
			j++
		}
		group := entries[i:j]
		groupStaged := []string{}
		// Review+build each pkgbase in this group
		for _, e := range group {
			pkgbase := e.Base
			reviewDir := p.ReviewDir(pkgbase)
			if _, err := os.Stat(filepath.Join(reviewDir, ".git")); err != nil {
				repo := fmt.Sprintf("https://aur.archlinux.org/%s.git", pkgbase)
				if err := run("git", "clone", repo, reviewDir); err != nil {
					return fmt.Errorf("git clone failed: %w", err)
				}
				_ = runC(reviewDir, "git", "checkout", "master")
			} else {
				if err := runC(reviewDir, "git", "fetch", "--all", "-p"); err != nil {
					return err
				}
				_ = runC(reviewDir, "git", "checkout", "master")
			}

			if !opt.NonInteractive {
				fmt.Printf("\nReviewing %s at %s\n", pkgbase, reviewDir)
				reader := bufio.NewReader(os.Stdin)
				for {
					// Determine upstream merge status
					merged := (runCQ(reviewDir, "git", "merge-base", "--is-ancestor", "origin/master", "HEAD") == nil)
					identical := (runCQ(reviewDir, "git", "diff", "--quiet", "origin/master") == nil)
					if merged {
						fmt.Print("[S]=shellcheck, [N]=namcap, [T]=shell, ")
						if identical {
							fmt.Print("[D]=(identical to upstream), ")
						} else {
							fmt.Print("[D]=view your changes, ")
						}
						fmt.Print("[O]=ok continue: ")
					} else {
						fmt.Print("[D]=view upstream changes, [M]=merge upstream, [T]=shell, [O]=(disabled until merge): ")
					}
					text, _ := reader.ReadString('\n')
					text = strings.ToLower(strings.TrimSpace(text))
					switch text {
					case "s":
						if merged {
							_ = shellcheck(reviewDir)
						}
					case "n":
						if merged {
							_ = namcap(reviewDir)
						}
					case "t":
						fmt.Println("Exit the shell with Ctrl-D...")
						_ = build.RunShell(reviewDir)
					case "d":
						if merged {
							_ = runC(reviewDir, "git", "--no-pager", "diff", "origin/master..HEAD")
						} else {
							_ = runC(reviewDir, "git", "--no-pager", "diff", "HEAD..origin/master")
						}
					case "m":
						if !merged {
							// Attempt a non-fast-forward merge of upstream
							if err := runC(reviewDir, "git", "merge", "--no-edit", "origin/master"); err != nil {
								fmt.Println("Merge failed. Resolve conflicts in the shell and try again.")
							}
						}
					case "o":
						if merged {
							goto BUILD
						}
					}
				}
			}
			if opt.NonInteractive {
				goto BUILD
			}
		BUILD:
			buildDir := p.BuildDir(pkgbase)
			_ = os.RemoveAll(buildDir)
			if err := os.MkdirAll(buildDir, 0o755); err != nil {
				return err
			}
			if err := build.CopyTree(reviewDir, buildDir); err != nil {
				return err
			}
			_ = os.RemoveAll(filepath.Join(buildDir, ".git"))
			if err := build.BuildDirectory(buildDir, p, opt.Offline, opt.Force, !opt.DisableSeccomp); err != nil {
				return err
			}
			files, _ := os.ReadDir(buildDir)
			var tars []string
			for _, f := range files {
				name := f.Name()
				if strings.HasSuffix(name, ".pkg.tar") || strings.HasSuffix(name, ".pkg.tar.xz") || strings.HasSuffix(name, ".pkg.tar.gz") || strings.HasSuffix(name, ".pkg.tar.zst") {
					tars = append(tars, filepath.Join(buildDir, name))
				}
			}
			// Filter artifacts by expected split package names for this pkgbase+depth
			var whitelist []string
			for name, base := range nameToBase {
				if base == pkgbase && plan.Depths[name] == depth {
					whitelist = append(whitelist, name)
				}
			}
			if len(whitelist) > 0 {
				tars = filterArtifactsByWhitelist(tars, whitelist)
			}
			for _, t := range tars {
				if err := tarcheck.TarCheck(t); err != nil {
					return err
				}
			}
			dstDir := p.CheckedTarsDir(pkgbase)
			for _, t := range tars {
				base := filepath.Base(t)
				dst := filepath.Join(dstDir, base)
				if err := moveCrossDevice(t, dst); err != nil {
					return err
				}
				groupStaged = append(groupStaged, dst)
				sigSrc := t + ".sig"
				if _, err := os.Stat(sigSrc); err == nil {
					_ = moveCrossDevice(sigSrc, dst+".sig")
				}
			}
			fmt.Printf("Artifacts staged at %s\n", dstDir)
		}
		// Install the whole group (depth>0 => asdeps)
		if opt.InstallBuilt && len(groupStaged) > 0 {
			asdeps := opt.AsDeps || depth > 0
			fmt.Printf("Installing %d artifact(s) via pacman -U (asdeps=%v) ...\n", len(groupStaged), asdeps)
			if err := pacman.InstallLocalWithMode(groupStaged, asdeps); err != nil {
				return fmt.Errorf("pacman -U failed: %w", err)
			}
		}
		i = j
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

// runCQ runs a command in dir and returns its exit status without attaching stdio
func runCQ(dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	return cmd.Run()
}

// wrappers
func shellcheck(dir string) error {
	return shellutil.Shellcheck(filepath.Join(dir, "PKGBUILD"), paths.Paths{})
}
func namcap(dir string) error { return shellutil.Namcap(filepath.Join(dir, "PKGBUILD"), paths.Paths{}) }

// filterArtifactsByWhitelist keeps only files whose parsed package name is in whitelist.
func filterArtifactsByWhitelist(files []string, whitelist []string) []string {
	allow := map[string]struct{}{}
	for _, w := range whitelist {
		allow[w] = struct{}{}
	}
	out := make([]string, 0, len(files))
	for _, f := range files {
		base := filepath.Base(f)
		name := parsePkgNameFromTar(base)
		if name == "" {
			continue
		}
		if _, ok := allow[name]; ok {
			out = append(out, f)
		}
	}
	return out
}

// parsePkgNameFromTar attempts to extract the package name from a file name
// like: <pkgname>-<pkgver>-<pkgrel>-<arch>.pkg.tar.*
// It returns empty string if parsing fails.
func parsePkgNameFromTar(filename string) string {
	// strip extension
	s := filename
	for _, suf := range []string{".pkg.tar.zst", ".pkg.tar.xz", ".pkg.tar.gz", ".pkg.tar.gzip", ".pkg.tar"} {
		if strings.HasSuffix(s, suf) {
			s = strings.TrimSuffix(s, suf)
			break
		}
	}
	// find last '-' (before arch)
	i := strings.LastIndexByte(s, '-')
	if i < 0 {
		return ""
	}
	s = s[:i]
	// find second last '-' (before pkgrel)
	i = strings.LastIndexByte(s, '-')
	if i < 0 {
		return ""
	}
	s = s[:i]
	// find third last '-' (before pkgver); pkgver may contain '-', so we remove one more hyphen
	i = strings.LastIndexByte(s, '-')
	if i < 0 {
		return ""
	}
	return s[:i]
}

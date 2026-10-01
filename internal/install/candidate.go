package install

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"go-rua/internal/reviewstate"
)

type boundedOutput struct {
	bytes.Buffer
	max int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.max {
		return 0, fmt.Errorf("command output exceeds limit")
	}
	return b.Buffer.Write(p)
}

var gitOutput = func(dir string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// Prevent hooks, external diff drivers, and replacement objects from changing review semantics.
	prefix := []string{"--no-replace-objects", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "--no-pager"}
	cmd := exec.CommandContext(ctx, "git", append(prefix, args...)...)
	cmd.Dir = dir
	var out boundedOutput
	out.max = reviewstate.MaxSnapshot * 2
	var stderr boundedOutput
	stderr.max = 64 << 10
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", args[0], err, stderr.String())
	}
	return out.Bytes(), nil
}

type candidate struct {
	commit      string
	recipe      reviewstate.Snapshot
	unpopulated bool
}

func prepareCandidate(dir, base string) (candidate, error) {
	var c candidate
	if !reviewstate.ValidName(base) {
		return c, fmt.Errorf("invalid package base %q", base)
	}
	if _, err := os.Lstat(filepath.Join(dir, ".git")); os.IsNotExist(err) {
		entries, e := os.ReadDir(dir)
		if e != nil {
			return c, e
		}
		if len(entries) != 0 {
			return c, fmt.Errorf("review directory is nonempty without a Git repository")
		}
		if _, err := gitOutput(dir, "clone", "--no-checkout", "--origin", "upstream", "--", "https://aur.archlinux.org/"+base+".git", "."); err != nil {
			return c, err
		}
		c.unpopulated = true
	} else if err != nil {
		return c, err
	}
	if !c.unpopulated {
		entries, e := os.ReadDir(dir)
		if e != nil {
			return c, e
		}
		if len(entries) == 1 && entries[0].Name() == ".git" {
			index, e := gitOutput(dir, "ls-files", "-z")
			if e != nil {
				return c, e
			}
			c.unpopulated = len(index) == 0
		}
	}
	if !c.unpopulated {
		if err := cleanCheckout(dir); err != nil {
			return c, err
		}
	}
	remote, err := gitOutput(dir, "remote", "get-url", "upstream")
	if err != nil {
		return c, err
	}
	if strings.TrimSpace(string(remote)) != "https://aur.archlinux.org/"+base+".git" {
		return c, fmt.Errorf("upstream remote differs from the canonical AUR package URL")
	}
	if _, err := gitOutput(dir, "fetch", "--no-tags", "upstream", "master"); err != nil {
		return c, err
	}
	commit, err := gitOutput(dir, "rev-parse", "--verify", "FETCH_HEAD^{commit}")
	if err != nil {
		return c, err
	}
	c.commit = strings.TrimSpace(string(commit))
	if _, err := gitOutput(dir, "merge-base", "--is-ancestor", "HEAD", c.commit); err != nil {
		return c, fmt.Errorf("checkout diverges from candidate; resolve local history before retrying: %w", err)
	}
	c.recipe, err = readGitSnapshot(dir, c.commit)
	return c, err
}
func cleanCheckout(dir string) error {
	out, err := gitOutput(dir, "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(out)) != 0 {
		return fmt.Errorf("review checkout has local changes; commit or remove them before retrying")
	}
	return nil
}
func readGitSnapshot(dir, commit string) (reviewstate.Snapshot, error) {
	out, err := gitOutput(dir, "ls-tree", "-rz", "--full-tree", commit)
	if err != nil {
		return nil, err
	}
	var s reviewstate.Snapshot
	total := 0
	for _, line := range bytes.Split(out, []byte{0}) {
		if len(line) == 0 {
			continue
		}
		header, name, ok := strings.Cut(string(line), "\t")
		fields := strings.Fields(header)
		if !ok || len(fields) != 3 || fields[1] != "blob" || (fields[0] != "100644" && fields[0] != "100755") {
			return nil, fmt.Errorf("unsupported recipe tree entry %q", string(line))
		}
		if len(s) >= 4096 {
			return nil, fmt.Errorf("too many recipe inputs")
		}
		data, err := gitOutput(dir, "cat-file", "blob", fields[2])
		if err != nil {
			return nil, err
		}
		total += len(data)
		if total > reviewstate.MaxSnapshot {
			return nil, fmt.Errorf("recipe snapshot exceeds limit")
		}
		mode := uint32(0644)
		if fields[0] == "100755" {
			mode = 0755
		}
		s = append(s, reviewstate.File{Path: name, Mode: mode, Data: data})
	}
	sort.Slice(s, func(i, j int) bool { return s[i].Path < s[j].Path })
	return s, s.Validate()
}
func mergeCandidate(dir string, c candidate) error {
	if c.unpopulated {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.Name() != ".git" {
				return fmt.Errorf("new checkout changed during review")
			}
		}
		if _, err := gitOutput(dir, "reset", "--mixed", c.commit); err != nil {
			return err
		}
		if err := c.recipe.Write(dir); err != nil {
			return err
		}
		return cleanCheckout(dir)
	}
	if err := cleanCheckout(dir); err != nil {
		return err
	}
	if _, err := gitOutput(dir, "merge", "--ff-only", "--no-edit", c.commit); err != nil {
		return err
	}
	s, err := reviewstate.Capture(dir, c.recipe.Names())
	if err != nil {
		return err
	}
	if s.Digest() != c.recipe.Digest() {
		return fmt.Errorf("checkout differs from approved recipe after merge")
	}
	return cleanCheckout(dir)
}

func recipeDiff(old, next reviewstate.Snapshot) string {
	var b strings.Builder
	names := map[string]bool{}
	for _, f := range old {
		names[f.Path] = true
	}
	for _, f := range next {
		names[f.Path] = true
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	for _, name := range ordered {
		a, z := old.Get(name), next.Get(name)
		var am, zm uint32
		for _, f := range old {
			if f.Path == name {
				am = f.Mode
			}
		}
		for _, f := range next {
			if f.Path == name {
				zm = f.Mode
			}
		}
		if bytes.Equal(a, z) && am == zm {
			continue
		}
		fmt.Fprintf(&b, "--- installed/%s (mode %04o)\n+++ candidate/%s (mode %04o)\n", name, am, name, zm)
		// Full file hunks deliberately retain every changed input, including binary bytes.
		if a != nil {
			for _, line := range strings.Split(string(a), "\n") {
				fmt.Fprintln(&b, "-"+line)
			}
		}
		if z != nil {
			for _, line := range strings.Split(string(z), "\n") {
				fmt.Fprintln(&b, "+"+line)
			}
		}
	}
	if b.Len() == 0 {
		return "Recipe is unchanged from the confirmed installed baseline.\n"
	}
	return b.String()
}

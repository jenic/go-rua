package install

import (
	"errors"
	"go-rua/internal/reviewstate"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCandidateFreezesFetchedCommitAndRejectsDirtyCheckout(t *testing.T) {
	for _, dirty := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean", true: "dirty"}[dirty], func(t *testing.T) {
			old := gitOutput
			defer func() { gitOutput = old }()
			commit := strings.Repeat("a", 40)
			gitOutput = func(_ string, args ...string) ([]byte, error) {
				switch args[0] {
				case "clone", "fetch", "merge-base":
					return nil, nil
				case "status":
					if dirty {
						return []byte(" M PKGBUILD\n"), nil
					}
					return nil, nil
				case "remote":
					return []byte("https://aur.archlinux.org/app.git\n"), nil
				case "rev-parse":
					return []byte(commit + "\n"), nil
				case "ls-tree":
					if args[len(args)-1] != commit {
						t.Fatal("mutable ref used")
					}
					return []byte("100644 blob " + strings.Repeat("b", 40) + "\tPKGBUILD\x00"), nil
				case "cat-file":
					return []byte("pkgname=app\n"), nil
				}
				return nil, errors.New("unexpected git command")
			}
			if dirty {
				if err := cleanCheckout(t.TempDir()); err == nil {
					t.Fatal("dirty checkout accepted")
				}
				return
			}
			c, err := prepareCandidate(t.TempDir(), "app")
			if (err != nil) != dirty {
				t.Fatal(err)
			}
			if !dirty && c.commit != commit {
				t.Fatal(c)
			}
		})
	}
}
func TestMergeChecksActualReviewedBytes(t *testing.T) {
	old := gitOutput
	defer func() { gitOutput = old }()
	commit := strings.Repeat("a", 40)
	gitOutput = func(_ string, args ...string) ([]byte, error) {
		if args[0] == "merge" && args[len(args)-1] != commit {
			t.Fatal("merge used mutable ref")
		}
		return nil, nil
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte("changed"), 0644)
	c := candidate{commit: commit, recipe: reviewstate.Snapshot{{Path: "PKGBUILD", Mode: 0644, Data: []byte("reviewed")}}}
	if err := mergeCandidate(dir, c); err == nil {
		t.Fatal("different checkout accepted")
	}
}

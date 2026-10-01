package pacman

import (
	"reflect"
	"strings"
	"testing"
)

func TestInstalledSnapshotPreservesSpaceInPaths(t *testing.T) {
	old := queryOutput
	defer func() { queryOutput = old }()
	queryOutput = func(args ...string) ([]byte, error) {
		if args[0] == "-Q" {
			return []byte("app 1-1\nother 2-1\n"), nil
		}
		return []byte("app /usr/\napp /usr/share/a file\nother /etc/other\n"), nil
	}
	s, err := InstalledSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !s.Files["app"]["usr/share/a file"] || !reflect.DeepEqual(s.Owners["etc/other"], []string{"other"}) {
		t.Fatal(s)
	}
}
func TestCheckMissingHandlesPacman127(t *testing.T) {
	dir := t.TempDir()
	writeExe(t, dir, "pacman", "echo 'lib>=2'\nexit 127")
	t.Setenv("PATH", dir)
	missing, err := CheckMissing([]string{"lib>=2"})
	if err != nil || strings.Join(missing, ",") != "lib>=2" {
		t.Fatal(missing, err)
	}
}

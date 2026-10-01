package tarcheck

import "testing"

func TestListArchivePreservesPrivilegesAndInstall(t *testing.T) {
	entries, install, err := listArchive(fixturePath(t))
	if err != nil {
		t.Fatal(err)
	}
	if install != "install script" || len(entries) != 3 || entries[2].Perm != "-rwsr-xr-x" {
		t.Fatalf("bad listing: %+v %q", entries, install)
	}
}

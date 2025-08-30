package tarcheck

import "testing"

func TestIsExec(t *testing.T) {
	cases := map[string]bool{
		"-rwxr-xr-x": true,
		"-rw-r--r--": false,
		"-rwsr-xr-x": true,
		"-rwSr--r--": false,
		"d---------": false,
		"":           false,
	}
	for perm, want := range cases {
		if got := isExec(perm); got != want {
			t.Fatalf("isExec(%q)=%v want %v", perm, got, want)
		}
	}
}

func TestIsSUID(t *testing.T) {
	cases := map[string]bool{
		"-rwsr-xr-x": true, // user s
		"-rwSr-xr-x": true, // user S
		"-rwxr-sr-x": true, // group s
		"-rwxr-Sr-x": true, // group S
		"-rwxr-xr-x": false,
		"":           false,
	}
	for perm, want := range cases {
		if got := isSUID(perm); got != want {
			t.Fatalf("isSUID(%q)=%v want %v", perm, got, want)
		}
	}
}

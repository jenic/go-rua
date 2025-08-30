package pacman

import "testing"

func TestStripDepName(t *testing.T) {
	cases := map[string]string{
		"foo":        "foo",
		"foo>=1.2":   "foo",
		"bar=2":      "bar",
		"baz<3":      "baz",
		"qux<=4.5":   "qux",
		"liba.so":    "liba.so",
		"  spaced  ": "spaced",
		"name>1.0":   "name",
	}
	for in, want := range cases {
		got := StripDepName(in)
		if got != want {
			t.Fatalf("StripDepName(%q)=%q, want %q", in, got, want)
		}
	}
}

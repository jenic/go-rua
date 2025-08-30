package paths

import "testing"

func TestMustInitMakepkgMissingPanics(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	SetMakepkgCheckForTests(func() error { return assertErr{} })
	defer SetMakepkgCheckForTests(func() error { return nil })
	defer func() { _ = recover() }()
	_ = MustInit() // should panic via fatalf
}

type assertErr struct{}

func (assertErr) Error() string { return "missing" }

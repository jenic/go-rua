package sandbox

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"
)

func TestReadStreamSeparatesStderrAndStopsFailedInspection(t *testing.T) {
	old := streamCommandHook
	defer func() { streamCommandHook = old }()
	streamCommandHook = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "printf payload; printf diagnostic >&2")
	}
	var got string
	if err := ReadStream(Config{}, []string{"test"}, func(r io.Reader) error { b, e := io.ReadAll(r); got = string(b); return e }); err != nil || got != "payload" {
		t.Fatal(got, err)
	}
	wanted := errors.New("bad archive")
	streamCommandHook = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "exec cat /dev/zero")
	}
	if err := ReadStream(Config{}, []string{"test"}, func(io.Reader) error { return wanted }); !errors.Is(err, wanted) {
		t.Fatal(err)
	}
	streamCommandHook = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "printf truncated; exit 2")
	}
	if err := ReadStream(Config{}, []string{"test"}, func(r io.Reader) error { _, e := io.Copy(io.Discard, r); return e }); err == nil || !strings.Contains(err.Error(), "exit status") {
		t.Fatal(err)
	}
}

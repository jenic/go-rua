//go:build linux

package main

import (
	"os"
	"os/exec"
	"testing"
)

func TestPrSetNoNewPrivsNoError(t *testing.T) {
	if err := prSetNoNewPrivs(); err != nil {
		t.Fatalf("prSetNoNewPrivs error: %v", err)
	}
}

func TestHelperSeccomp(t *testing.T) {
	if os.Getenv("RUN_SECCOMP_HELPER") != "1" {
		t.Skip("helper")
	}
	// Ensure it returns without error
	if err := applySeccompDenylist(); err != nil {
		t.Fatalf("applySeccompDenylist error: %v", err)
	}
	os.Exit(0)
}

func TestApplySeccompDenylistInChild(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperSeccomp")
	cmd.Env = append(os.Environ(), "RUN_SECCOMP_HELPER=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child failed: %v, out=%s", err, string(out))
	}
}

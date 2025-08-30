//go:build linux

package main

import (
	"syscall"
)

func syscallExecRaw(prog string, args []string, env []string) error {
	return syscall.Exec(prog, args, env)
}

// prSetNoNewPrivs sets PR_SET_NO_NEW_PRIVS=1 if supported.
func prSetNoNewPrivs() error {
	// Ignore error if not supported
	const _PR_SET_NO_NEW_PRIVS = 38
	_, _, _ = syscall.Syscall6(syscall.SYS_PRCTL, _PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0)
	return nil
}

//go:build linux

package main

import (
	"syscall"
)

func syscallExecRaw(prog string, args []string, env []string) error {
	return syscall.Exec(prog, args, env)
}

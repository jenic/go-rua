//go:build linux

package main

import (
    "unsafe"
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

// applySeccompDenylist installs a minimal seccomp-bpf filter that denies
// a small set of risky syscalls and allows all others. Best-effort.
func applySeccompDenylist() error {
    // BPF helpers and constants (classic BPF)
    const (
        // instruction classes
        _BPF_LD  = 0x00
        _BPF_JMP = 0x05
        _BPF_RET = 0x06
        // sizes
        _BPF_W = 0x00
        // modes
        _BPF_ABS = 0x20
        // ops
        _BPF_JEQ = 0x10
        // src
        _BPF_K = 0x00

        // seccomp return codes
        _SECCOMP_RET_KILL_PROCESS = 0x80000000
        _SECCOMP_RET_ALLOW        = 0x7fff0000
        _SECCOMP_RET_ERRNO        = 0x00050000

        // prctl constants
        _PR_SET_SECCOMP    = 22
        _SECCOMP_MODE_FILTER = 2

        // audit arch
        _AUDIT_ARCH_X86_64 = 0xc000003e
    )

    // helpers to compose instructions
    insn := func(code uint16, jt, jf uint8, k uint32) syscall.SockFilter {
        return syscall.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
    }
    // convenience creators
    ldAbsW := func(k uint32) syscall.SockFilter { return insn(_BPF_LD|_BPF_W|_BPF_ABS, 0, 0, k) }
    jeq := func(k uint32, jt, jf uint8) syscall.SockFilter { return insn(_BPF_JMP|_BPF_JEQ|_BPF_K, jt, jf, k) }
    ret := func(k uint32) syscall.SockFilter { return insn(_BPF_RET|_BPF_K, 0, 0, k) }

    // denylist of syscalls (x86_64 numbers)
    const (
        _NR_PTRACE            = 101
        _NR_BPF               = 321
        _NR_USERFAULTFD       = 323
        _NR_KEXEC_LOAD        = 246
        _NR_KEXEC_FILE_LOAD   = 320
        _NR_PERF_EVENT_OPEN   = 298
        _NR_OPEN_BY_HANDLE_AT = 304
        _NR_NAME_TO_HANDLE_AT = 303
        _NR_SETNS             = 308
        _NR_MOUNT             = 165
        _NR_UMOUNT2           = 166
        _NR_PIVOT_ROOT        = 155
        _NR_INIT_MODULE       = 175
        _NR_FINIT_MODULE      = 313
        _NR_DELETE_MODULE     = 176
        _NR_KEYCTL            = 250
        _NR_ADD_KEY           = 248
        _NR_REQUEST_KEY       = 249
    )
    denies := []uint32{
        _NR_PTRACE,
        _NR_BPF,
        _NR_USERFAULTFD,
        _NR_KEXEC_LOAD,
        _NR_KEXEC_FILE_LOAD,
        _NR_PERF_EVENT_OPEN,
        _NR_OPEN_BY_HANDLE_AT,
        _NR_NAME_TO_HANDLE_AT,
        _NR_SETNS,
        _NR_MOUNT,
        _NR_UMOUNT2,
        _NR_PIVOT_ROOT,
        _NR_INIT_MODULE,
        _NR_FINIT_MODULE,
        _NR_DELETE_MODULE,
        _NR_KEYCTL,
        _NR_ADD_KEY,
        _NR_REQUEST_KEY,
    }

    // Build filter: check arch, then syscall number, deny matching, allow otherwise.
    prog := make([]syscall.SockFilter, 0, 4+2*len(denies)+1)
    // load arch (offset 4 in struct seccomp_data)
    prog = append(prog, ldAbsW(4))
    // if arch == x86_64, skip next instruction, else KILL
    prog = append(prog, jeq(_AUDIT_ARCH_X86_64, 1, 0))
    prog = append(prog, ret(_SECCOMP_RET_KILL_PROCESS))
    // load syscall number (offset 0)
    prog = append(prog, ldAbsW(0))
    // For each deny syscall: if equal, RET ERRNO(EPERM), else continue
    for _, nr := range denies {
        prog = append(prog, jeq(nr, 0, 1))
        prog = append(prog, ret(_SECCOMP_RET_ERRNO|uint32(syscall.EPERM)))
    }
    // default allow
    prog = append(prog, ret(_SECCOMP_RET_ALLOW))

    fprog := syscall.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}

    // no_new_privs required before installing a filter
    _ = prSetNoNewPrivs()
    _, _, e := syscall.Syscall6(syscall.SYS_PRCTL, _PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&fprog)), 0, 0, 0)
    if e != 0 {
        return e
    }
    return nil
}

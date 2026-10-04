package main

import (
	"fmt"
	"os"

	ll "github.com/landlock-lsm/go-landlock/landlock"
	"golang.org/x/sys/unix"
)

const (
	landlockRead  ll.AccessFSSet = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR
	landlockExec  ll.AccessFSSet = unix.LANDLOCK_ACCESS_FS_EXECUTE
	landlockWrite ll.AccessFSSet = unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_TRUNCATE |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM | unix.LANDLOCK_ACCESS_FS_REFER
	landlockFileRights ll.AccessFSSet = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_TRUNCATE
)

type landlockGrant struct {
	path   string
	rights ll.AccessFSSet
}

// landlockGrants resolves path types before enforcement. Only built-in paths
// may be absent; a missing explicitly configured path is a policy error.
func landlockGrants(cfg sandboxExecConfig) ([]landlockGrant, error) {
	var grants []landlockGrant
	add := func(paths []string, rights ll.AccessFSSet, optional bool) error {
		for _, path := range paths {
			if path == "" {
				continue
			}
			st, err := os.Stat(path)
			if optional && os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return fmt.Errorf("inspect Landlock path %q: %w", path, err)
			}
			access := rights
			if !st.IsDir() {
				access &= landlockFileRights
			}
			grants = append(grants, landlockGrant{path, access})
		}
		return nil
	}
	for _, group := range []struct {
		defaults, configured []string
		rights               ll.AccessFSSet
	}{
		{[]string{"/etc", "/proc", "/sys"}, cfg.RO, landlockRead},
		{[]string{"/usr", "/bin", "/sbin", "/lib", "/lib64"}, cfg.ROX, landlockRead | landlockExec},
		{[]string{"/dev/null", "/dev/tty", "/dev/pts", "/dev/shm"}, cfg.RW, landlockRead | landlockWrite},
		{[]string{"/tmp", "/var/tmp"}, cfg.RWX, landlockRead | landlockWrite | landlockExec},
	} {
		if err := add(group.defaults, group.rights, true); err != nil {
			return nil, err
		}
		if err := add(group.configured, group.rights, false); err != nil {
			return nil, err
		}
	}
	return grants, nil
}

func applyLandlock(cfg sandboxExecConfig) error {
	grants, err := landlockGrants(cfg)
	if err != nil {
		return err
	}
	rules := make([]ll.Rule, 0, len(grants))
	for _, grant := range grants {
		rules = append(rules, ll.PathAccess(grant.rights, grant.path))
	}
	// V3 includes truncation protection. Never silently downgrade to a no-op:
	// sandboxExec handles errors and the explicitly requested BestEffort mode.
	// Upstream enforces the policy and no_new_privs on all Go/CGO threads.
	if err := ll.V3.RestrictPaths(rules...); err != nil {
		return fmt.Errorf("enforce Landlock ABI 3 filesystem policy: %w", err)
	}
	return nil
}

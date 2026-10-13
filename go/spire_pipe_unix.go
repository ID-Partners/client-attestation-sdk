//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package clientattestation

import (
	"os"

	"golang.org/x/sys/unix"
)

// pipePending is how many bytes are waiting in the pipe r (FIONREAD), or 0 if that can't be told.
func pipePending(r *os.File) int {
	conn, err := r.SyscallConn()
	if err != nil {
		return 0
	}
	n := 0
	_ = conn.Control(func(fd uintptr) {
		if v, err := unix.IoctlGetInt(int(fd), fionread); err == nil {
			n = v
		}
	})
	return n
}

package clientattestation

import "golang.org/x/sys/unix"

// fionread is the ioctl that tells how many bytes are waiting in a pipe (FIONREAD, TIOCINQ on Linux).
const fionread = unix.TIOCINQ

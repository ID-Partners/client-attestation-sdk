//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package clientattestation

// fionread is the ioctl that tells how many bytes are waiting in a pipe: FIONREAD, _IOR('f', 127, int).
const fionread = 0x4004667f

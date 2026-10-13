//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package clientattestation

import "os"

// pipePending is 0 where the pipe is not asked how much is waiting in it (Windows, say): there, output the
// agent writes past the cap just before it exits may be read either side of its exit.
func pipePending(*os.File) int { return 0 }

//go:build unix

package clientattestation

import (
	"errors"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestFileTokenSvidSourceRefusesNonRegularFile(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fifo, "/dev/zero"} {
		done := make(chan error, 1)
		go func() {
			_, err := (FileTokenSvidSource{Path: path}).Fetch("aud")
			done <- err
		}()
		select {
		case err := <-done:
			var nf *EvidenceNotFound
			if !errors.As(err, &nf) || !strings.Contains(err.Error(), "not a regular file") {
				t.Fatalf("%s: err = %v, want *EvidenceNotFound", path, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: Fetch hung", path)
		}
	}
}

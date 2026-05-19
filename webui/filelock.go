package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// ErrFlockTimeout is returned when the exclusive lock cannot be acquired
// before the specified deadline.
var ErrFlockTimeout = errors.New("flock: timeout acquiring exclusive lock")

// flockPollInterval is the back-off between non-blocking flock attempts.
// Short enough that contention with tls-proxy resolves within tens of ms,
// long enough not to spin a CPU under heavy lock contention.
const flockPollInterval = 25 * time.Millisecond

// WithFlock acquires an exclusive advisory lock on path (creating it if
// needed), runs fn, then releases the lock and closes the file.
//
// The lock file is a sidecar (typical name: "<target>.lock") shared between
// the webui (issuer) and tls-proxy (consumer) so both can perform safe
// read-modify-write on enroll-tokens.json.
//
// Implementation notes:
//   - Uses LOCK_EX | LOCK_NB in a poll loop to honour the timeout. flock(2)
//     itself has no timeout, so blocking + a separate timer would race against
//     the syscall. Polling is simple, correct, and the contention window is
//     sub-millisecond in practice.
//   - The lock file is intentionally NOT removed on release. Removing it
//     would race with another process opening the same path; the file is
//     persistent and 0600.
//   - fn must not call WithFlock recursively on the same path (POSIX flock
//     is per-fd, not per-pid, but nested locking is still a smell — make the
//     critical section flat).
func WithFlock(path string, timeout time.Duration, fn func() error) error {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("flock: open %s: %w", path, err)
	}
	// Make sure we always close, even on panic from fn.
	defer f.Close()

	deadline := time.Now().Add(timeout)
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break // got the lock
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return fmt.Errorf("flock: %s: %w", path, err)
		}
		if time.Now().After(deadline) {
			return ErrFlockTimeout
		}
		time.Sleep(flockPollInterval)
	}
	// Best-effort unlock (close also drops the lock, but explicit unlock helps
	// if fn panics and the deferred close runs after recovery elsewhere).
	defer func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	}()

	return fn()
}

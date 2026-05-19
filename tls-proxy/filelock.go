// filelock.go: thin OS-level file lock (LOCK_EX via flock(2)) used to
// coordinate /config/enroll-tokens.json access between tls-proxy and webui.
//
// Both processes run on Linux containers; this file deliberately uses the
// Linux-only golang.org/x/sys/unix package. A non-Linux build would require
// a stub.
//
// Usage:
//
//   err := WithFlock("/config/enroll-tokens.json.lock", 5*time.Second, func() error {
//       // read-modify-write the JSON file here
//   })
//   if errors.Is(err, ErrFlockTimeout) {
//       // return 503 Service Unavailable + Retry-After
//   }
//
// The lock target is a sidecar file (path + ".lock" by convention used in
// this project) so the lock survives atomic rename of the data file.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// ErrFlockTimeout is returned by WithFlock when the lock could not be
// acquired within the deadline. Callers may surface this as a transient
// error suitable for client retry.
var ErrFlockTimeout = errors.New("flock acquisition timed out")

// flockPollInterval is how often we retry LOCK_EX|LOCK_NB until the
// timeout fires. 50ms keeps p99 contention latency low while bounding
// CPU spend during pathological contention.
const flockPollInterval = 50 * time.Millisecond

// WithFlock acquires an exclusive flock on path for the duration of fn.
// The lock file is created (mode 0600) if missing. Lock is released on
// return regardless of fn's error.
//
// timeout <= 0 means "do not wait — fail fast if not immediately available".
func WithFlock(path string, timeout time.Duration, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("flock mkdir %s: %w", filepath.Dir(path), err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("flock open %s: %w", path, err)
	}
	defer f.Close()

	deadline := time.Now().Add(timeout)
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && err != unix.EAGAIN {
			return fmt.Errorf("flock %s: %w", path, err)
		}
		if timeout <= 0 || time.Now().After(deadline) {
			return ErrFlockTimeout
		}
		time.Sleep(flockPollInterval)
	}
	defer func() {
		// Best-effort unlock. The defer on f.Close() above also drops it.
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	}()

	return fn()
}

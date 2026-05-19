package main

import (
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWithFlockBasic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.lock")
	called := false
	err := WithFlock(path, time.Second, func() error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !called {
		t.Fatal("fn was not invoked")
	}
}

// TestWithFlockTimeoutOnContention starts one long-holding lock owner and
// asserts that a second caller times out cleanly with ErrFlockTimeout.
func TestWithFlockTimeoutOnContention(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "busy.lock")

	holderEntered := make(chan struct{})
	holderRelease := make(chan struct{})
	holderDone := make(chan struct{})

	go func() {
		_ = WithFlock(path, 5*time.Second, func() error {
			close(holderEntered)
			<-holderRelease
			return nil
		})
		close(holderDone)
	}()

	<-holderEntered
	// Now contend with a short timeout.
	start := time.Now()
	err := WithFlock(path, 200*time.Millisecond, func() error {
		t.Fatal("inner fn must not run while another holder is active")
		return nil
	})
	elapsed := time.Since(start)
	if !errors.Is(err, ErrFlockTimeout) {
		t.Fatalf("expected ErrFlockTimeout, got %v", err)
	}
	if elapsed < 150*time.Millisecond {
		t.Errorf("expected to wait at least ~200ms, got %s", elapsed)
	}
	if elapsed > 1*time.Second {
		t.Errorf("waited too long for timeout: %s", elapsed)
	}

	close(holderRelease)
	<-holderDone
}

// TestWithFlockSerialisesContenders runs many goroutines all acquiring the
// same lock; their critical sections must never overlap.
func TestWithFlockSerialisesContenders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "serial.lock")

	var (
		inFlight int32
		violated atomic.Bool
		wg       sync.WaitGroup
	)
	const n = 10
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := WithFlock(path, 5*time.Second, func() error {
				if atomic.AddInt32(&inFlight, 1) != 1 {
					violated.Store(true)
				}
				time.Sleep(20 * time.Millisecond)
				atomic.AddInt32(&inFlight, -1)
				return nil
			})
			if err != nil {
				t.Errorf("flock err: %v", err)
			}
		}()
	}
	wg.Wait()
	if violated.Load() {
		t.Fatal("critical sections overlapped — flock not serialising")
	}
}

// TestWithFlockReleasedOnFnError ensures a returning-error fn still releases
// the lock so subsequent callers can proceed.
func TestWithFlockReleasedOnFnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rel.lock")
	sentinel := errors.New("boom")
	err := WithFlock(path, time.Second, func() error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel, got %v", err)
	}
	// Second acquire must succeed promptly.
	start := time.Now()
	err = WithFlock(path, 200*time.Millisecond, func() error { return nil })
	if err != nil {
		t.Fatalf("second acquire failed: %v", err)
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Errorf("second acquire took too long: %s", time.Since(start))
	}
}

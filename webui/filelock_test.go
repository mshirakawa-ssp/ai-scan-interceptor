package main

import (
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWithFlock_BasicHold(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "x.lock")

	called := false
	err := WithFlock(lock, time.Second, func() error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("WithFlock: %v", err)
	}
	if !called {
		t.Fatal("fn not invoked")
	}

	// Second call should still succeed (lock was released).
	err = WithFlock(lock, time.Second, func() error { return nil })
	if err != nil {
		t.Fatalf("second WithFlock: %v", err)
	}
}

func TestWithFlock_PropagatesError(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "x.lock")
	myErr := errors.New("inside fn")
	err := WithFlock(lock, time.Second, func() error { return myErr })
	if !errors.Is(err, myErr) {
		t.Fatalf("expected fn error, got: %v", err)
	}
}

// TestWithFlock_Mutex verifies that two concurrent goroutines never run their
// critical sections simultaneously. We use an atomic guard counter instead of
// timing because timing is flaky in CI.
func TestWithFlock_Mutex(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "mx.lock")

	var inside int32
	var maxInside int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := WithFlock(lock, 5*time.Second, func() error {
				cur := atomic.AddInt32(&inside, 1)
				for {
					prev := atomic.LoadInt32(&maxInside)
					if cur <= prev || atomic.CompareAndSwapInt32(&maxInside, prev, cur) {
						break
					}
				}
				time.Sleep(20 * time.Millisecond)
				atomic.AddInt32(&inside, -1)
				return nil
			})
			if err != nil {
				t.Errorf("WithFlock: %v", err)
			}
		}()
	}
	wg.Wait()
	if max := atomic.LoadInt32(&maxInside); max != 1 {
		t.Fatalf("max concurrent inside = %d (want 1)", max)
	}
}

// TestWithFlock_Timeout starts a long-running holder and expects a fast caller
// to time out quickly.
func TestWithFlock_Timeout(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "t.lock")

	holderRunning := make(chan struct{})
	holderRelease := make(chan struct{})
	holderDone := make(chan struct{})
	go func() {
		_ = WithFlock(lock, 5*time.Second, func() error {
			close(holderRunning)
			<-holderRelease
			return nil
		})
		close(holderDone)
	}()
	<-holderRunning

	start := time.Now()
	err := WithFlock(lock, 200*time.Millisecond, func() error {
		t.Fatal("fn should not run while holder has lock")
		return nil
	})
	elapsed := time.Since(start)
	if !errors.Is(err, ErrFlockTimeout) {
		t.Fatalf("expected ErrFlockTimeout, got %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("timeout took too long: %v", elapsed)
	}
	close(holderRelease)
	<-holderDone
}

func TestWithFlock_DefaultTimeout(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "d.lock")
	// timeout <= 0 should fall back to a sensible default and still run fn.
	err := WithFlock(lock, 0, func() error { return nil })
	if err != nil {
		t.Fatalf("WithFlock(0): %v", err)
	}
}

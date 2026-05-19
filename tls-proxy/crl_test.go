package main

import (
	"context"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeCRL is a test helper that writes a revoked-serials.json file with the
// given serials.
func writeCRL(t *testing.T, path string, serials ...string) {
	t.Helper()
	recs := make([]revokedRecord, 0, len(serials))
	for _, s := range serials {
		recs = append(recs, revokedRecord{SerialHex: s, RevokedAt: time.Now().UTC()})
	}
	data, err := json.MarshalIndent(revokedFileSchema{Version: 1, Revoked: recs}, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write CRL: %v", err)
	}
}

func TestRevokedStoreIsRevoked(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "revoked-serials.json")
	writeCRL(t, path, "0a1b2c", "DEADBEEF")

	store, err := LoadRevokedStore(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := store.Size(); got != 2 {
		t.Errorf("size: want 2, got %d", got)
	}

	// Hex form, exact match.
	s1, _ := new(big.Int).SetString("0a1b2c", 16)
	if !store.IsRevoked(s1) {
		t.Error("expected 0a1b2c to be revoked")
	}
	// Case-insensitive: serialised by Text(16) which is lowercase.
	s2, _ := new(big.Int).SetString("deadbeef", 16)
	if !store.IsRevoked(s2) {
		t.Error("expected deadbeef to be revoked")
	}
	// Negative case.
	s3, _ := new(big.Int).SetString("ff", 16)
	if store.IsRevoked(s3) {
		t.Error("0xff should not be revoked")
	}
	// Nil-safe.
	var nilStore *RevokedStore
	if nilStore.IsRevoked(s1) {
		t.Error("nil store should report false")
	}
	if store.IsRevoked(nil) {
		t.Error("nil serial should report false")
	}
}

func TestRevokedStoreMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.json")

	store, err := LoadRevokedStore(path)
	if err != nil {
		t.Fatalf("missing file should not error, got %v", err)
	}
	if store.Size() != 0 {
		t.Errorf("expected empty, got %d", store.Size())
	}
	s, _ := new(big.Int).SetString("0a", 16)
	if store.IsRevoked(s) {
		t.Error("nothing should be revoked when file is missing")
	}
}

func TestRevokedStoreEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(path, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := LoadRevokedStore(path)
	if err != nil {
		t.Fatalf("empty file should not error, got %v", err)
	}
	if store.Size() != 0 {
		t.Errorf("expected 0 entries, got %d", store.Size())
	}
}

func TestRevokedStoreMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRevokedStore(path); err == nil {
		t.Fatal("malformed JSON should return an error")
	}
}

func TestRevokedStoreReloaderPicksUpChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "revoked-serials.json")
	writeCRL(t, path, "aa")

	store, err := LoadRevokedStore(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !store.IsRevokedHex("aa") {
		t.Fatal("aa must be revoked initially")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store.StartReloader(ctx, path, 50*time.Millisecond)

	// Update the file with a new serial.
	writeCRL(t, path, "bb", "cc")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if store.IsRevokedHex("bb") && store.IsRevokedHex("cc") && !store.IsRevokedHex("aa") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("reloader did not pick up new file within deadline; size=%d aa=%v bb=%v cc=%v",
		store.Size(), store.IsRevokedHex("aa"), store.IsRevokedHex("bb"), store.IsRevokedHex("cc"))
}

func TestRevokedStoreNormalizesSerial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "revoked-serials.json")

	// Write the serial in unusual forms; all should match the canonical
	// lowercase-no-separator form when looking up.
	writeCRL(t, path, "0xAB:CD-EF", "  12 34 ")

	store, err := LoadRevokedStore(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !store.IsRevokedHex("abcdef") {
		t.Error("0xAB:CD-EF should normalise to abcdef")
	}
	if !store.IsRevokedHex("1234") {
		t.Error("'  12 34 ' should normalise to 1234")
	}
}

func TestRevokedStoreNilHandling(t *testing.T) {
	var s *RevokedStore
	if s.IsRevokedHex("anything") {
		t.Error("nil store should report false on hex lookup")
	}
	if s.Size() != 0 {
		t.Error("nil store size should be 0")
	}
	if !s.LoadedAt().IsZero() {
		t.Error("nil store LoadedAt should be zero")
	}
}

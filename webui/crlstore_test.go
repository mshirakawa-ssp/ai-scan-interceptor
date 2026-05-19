package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCRLStore_AddAndPersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "revoked-serials.json")
	s, err := newCRLStore(path)
	if err != nil {
		t.Fatalf("newCRLStore: %v", err)
	}
	if got := s.List(); len(got) != 0 {
		t.Fatalf("initial len=%d", len(got))
	}

	if err := s.Add("0A1B2C", "alice@WIN-042"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// Adding the same (case-insensitive) again is a no-op.
	if err := s.Add("0a1b2c", "anyone-else"); err != nil {
		t.Fatalf("Add idempotent: %v", err)
	}
	list := s.List()
	if len(list) != 1 {
		t.Fatalf("len=%d after duplicate Add", len(list))
	}
	if list[0].SerialHex != "0a1b2c" {
		t.Fatalf("serial=%q (expected lowercased)", list[0].SerialHex)
	}
	if list[0].Subject != "alice@WIN-042" {
		t.Fatalf("subject=%q (first wins)", list[0].Subject)
	}
	if list[0].RevokedAt.IsZero() {
		t.Fatal("revoked_at zero")
	}

	// Has must be case-insensitive too.
	if !s.Has("0A1B2C") {
		t.Fatal("Has miss for upper case")
	}
	if !s.Has("0a:1b:2c") {
		t.Fatal("Has miss for colon-formatted serial")
	}
	if s.Has("ffff") {
		t.Fatal("Has hit for unknown serial")
	}

	// Validate on-disk schema matches the contract with tls-proxy.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	var disk struct {
		Version int            `json:"version"`
		Revoked []RevokedEntry `json:"revoked"`
	}
	if err := json.Unmarshal(data, &disk); err != nil {
		t.Fatalf("unmarshal disk: %v", err)
	}
	if disk.Version != crlSchemaVersion {
		t.Fatalf("version on disk=%d (want %d)", disk.Version, crlSchemaVersion)
	}
	if len(disk.Revoked) != 1 || disk.Revoked[0].SerialHex != "0a1b2c" {
		t.Fatalf("disk revoked=%+v", disk.Revoked)
	}
	info, _ := os.Stat(path)
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Fatalf("file perm=%o (want 0600)", mode)
	}
}

func TestCRLStore_Remove(t *testing.T) {
	dir := t.TempDir()
	s, _ := newCRLStore(filepath.Join(dir, "r.json"))
	_ = s.Add("aaaa", "u1")
	_ = s.Add("bbbb", "u2")

	if err := s.Remove("AAAA"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if s.Has("aaaa") {
		t.Fatal("still revoked after Remove")
	}
	if !s.Has("bbbb") {
		t.Fatal("Remove dropped wrong entry")
	}

	// Removing non-existent serial is a no-op.
	if err := s.Remove("ffff"); err != nil {
		t.Fatalf("Remove unknown: %v", err)
	}
}

func TestCRLStore_Reload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "r.json")
	s, _ := newCRLStore(path)
	_ = s.Add("1234", "u1")

	// External writer dumps a different CRL onto disk.
	external := crlFile{
		Version: 1,
		Revoked: []RevokedEntry{
			{SerialHex: "deadbeef", Subject: "ext"},
		},
	}
	data, _ := json.MarshalIndent(external, "", "  ")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("external write: %v", err)
	}

	if err := s.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !s.Has("deadbeef") {
		t.Fatal("Reload did not pick up external write")
	}
	if s.Has("1234") {
		t.Fatal("Reload kept stale in-memory entry")
	}
}

func TestCRLStore_RejectsEmptySerial(t *testing.T) {
	dir := t.TempDir()
	s, _ := newCRLStore(filepath.Join(dir, "r.json"))
	if err := s.Add("", "x"); err == nil {
		t.Fatal("expected error on empty serial")
	}
	if err := s.Add("   ", "x"); err == nil {
		t.Fatal("expected error on whitespace serial")
	}
	if err := s.Remove(""); err == nil {
		t.Fatal("expected error on empty Remove")
	}
}

func TestCRLStore_MissingFileIsEmpty(t *testing.T) {
	dir := t.TempDir()
	s, err := newCRLStore(filepath.Join(dir, "does-not-exist.json"))
	if err != nil {
		t.Fatalf("newCRLStore on missing file: %v", err)
	}
	if got := s.List(); len(got) != 0 {
		t.Fatalf("expected empty list, got %d entries", len(got))
	}
}

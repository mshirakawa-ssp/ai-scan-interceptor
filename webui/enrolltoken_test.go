package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEnrollTokenStore_CreateListRevoke(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enroll-tokens.json")
	s, err := newEnrollTokenStore(path)
	if err != nil {
		t.Fatalf("newEnrollTokenStore: %v", err)
	}

	tok, plaintext, err := s.Create(CreateOptions{
		Description:    "test desc",
		ExpiresInHours: 1,
		MaxUses:        1,
		CreatedBy:      "admin",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if plaintext == "" {
		t.Fatal("plaintext empty")
	}
	if tok.TokenHash == "" {
		t.Fatal("token hash empty")
	}
	if tok.TokenHash == plaintext {
		t.Fatal("hash equal to plaintext")
	}
	if tok.MaxUses != 1 {
		t.Fatalf("max_uses=%d", tok.MaxUses)
	}

	// Reload and verify the hash persisted.
	s2, err := newEnrollTokenStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	list := s2.List()
	if len(list) != 1 {
		t.Fatalf("list len=%d", len(list))
	}
	if list[0].TokenHash != tok.TokenHash {
		t.Fatalf("hash differs after reload")
	}
	if list[0].ID != tok.ID {
		t.Fatalf("id differs after reload")
	}
	// Plaintext must NOT be in the persisted record.
	if list[0].TokenHash == plaintext {
		t.Fatal("plaintext leaked into TokenHash")
	}

	// Revoke
	if err := s2.Revoke(tok.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	got, ok := s2.GetByID(tok.ID)
	if !ok {
		t.Fatal("not found after revoke")
	}
	if !got.Revoked {
		t.Fatal("not flagged revoked")
	}
	if got.RevokedAt == nil {
		t.Fatal("revoked_at nil")
	}

	// Revoke unknown
	if err := s2.Revoke("does-not-exist"); err == nil {
		t.Fatal("expected error revoking unknown")
	}
}

func TestEnrollTokenStore_DefaultsAndLimits(t *testing.T) {
	dir := t.TempDir()
	s, _ := newEnrollTokenStore(filepath.Join(dir, "t.json"))

	tok, _, err := s.Create(CreateOptions{Description: "defaults"})
	if err != nil {
		t.Fatalf("Create defaults: %v", err)
	}
	if tok.MaxUses != 1 {
		t.Fatalf("default max_uses=%d", tok.MaxUses)
	}

	if _, _, err := s.Create(CreateOptions{ExpiresInHours: 99999}); err == nil {
		t.Fatal("expected error for too-long expiry")
	}
	if _, _, err := s.Create(CreateOptions{MaxUses: 99999}); err == nil {
		t.Fatal("expected error for too-many uses")
	}
}

func TestEnrollTokenStore_Delete(t *testing.T) {
	dir := t.TempDir()
	s, _ := newEnrollTokenStore(filepath.Join(dir, "t.json"))
	tok, _, _ := s.Create(CreateOptions{Description: "x"})
	if err := s.Delete(tok.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := s.GetByID(tok.ID); ok {
		t.Fatal("still present after delete")
	}
}

// TestEnrollTokenStore_PreservesExternalUsedCount simulates tls-proxy
// incrementing used_count between webui's Create and webui's Revoke. The
// flock + reload-before-write design must keep tls-proxy's increment.
func TestEnrollTokenStore_PreservesExternalUsedCount(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enroll-tokens.json")
	s, err := newEnrollTokenStore(path)
	if err != nil {
		t.Fatalf("newEnrollTokenStore: %v", err)
	}
	tok, _, err := s.Create(CreateOptions{Description: "concurrent", MaxUses: 5})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// External writer (tls-proxy) bumps used_count from 0 to 3.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var disk []*EnrollToken
	if err := json.Unmarshal(raw, &disk); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, d := range disk {
		if d.ID == tok.ID {
			d.UsedCount = 3
		}
	}
	out, _ := json.MarshalIndent(disk, "", "  ")
	if err := os.WriteFile(path, out, 0600); err != nil {
		t.Fatalf("external write: %v", err)
	}

	// webui revokes; the reload-before-write flow must observe used_count=3.
	if err := s.Revoke(tok.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	raw, _ = os.ReadFile(path)
	var after []*EnrollToken
	_ = json.Unmarshal(raw, &after)
	var found *EnrollToken
	for _, d := range after {
		if d.ID == tok.ID {
			found = d
			break
		}
	}
	if found == nil {
		t.Fatal("token disappeared")
	}
	if found.UsedCount != 3 {
		t.Fatalf("used_count=%d (want 3 — external write was lost)", found.UsedCount)
	}
	if !found.Revoked {
		t.Fatal("revoke flag not set")
	}
}

// TestEnrollTokenStore_ReloadSurfacesExternalChanges verifies that GET
// /api/enroll-tokens (which calls Reload) picks up tls-proxy's writes.
func TestEnrollTokenStore_ReloadSurfacesExternalChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "t.json")
	s, _ := newEnrollTokenStore(path)
	tok, _, _ := s.Create(CreateOptions{Description: "x", MaxUses: 10})

	// External bump.
	raw, _ := os.ReadFile(path)
	var disk []*EnrollToken
	_ = json.Unmarshal(raw, &disk)
	for _, d := range disk {
		if d.ID == tok.ID {
			d.UsedCount = 7
		}
	}
	out, _ := json.MarshalIndent(disk, "", "  ")
	_ = os.WriteFile(path, out, 0600)

	if err := s.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	got, ok := s.GetByID(tok.ID)
	if !ok {
		t.Fatal("not found after reload")
	}
	if got.UsedCount != 7 {
		t.Fatalf("used_count=%d (want 7)", got.UsedCount)
	}
}

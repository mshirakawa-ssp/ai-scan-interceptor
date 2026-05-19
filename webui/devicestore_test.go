package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDeviceStore_AddListGet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "devices.json")
	s, err := newDeviceStore(path)
	if err != nil {
		t.Fatalf("newDeviceStore: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	d := Device{
		DeviceID:  "dev-001",
		Subject:   "alice@WIN-042",
		Org:       "acme",
		IssuedAt:  now,
		ExpiresAt: now.Add(7 * 24 * time.Hour),
	}
	if err := s.Add(d); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := s.Add(d); err == nil {
		t.Fatal("expected error adding duplicate device_id")
	}

	got, ok := s.GetByID("dev-001")
	if !ok {
		t.Fatal("not found")
	}
	if got.Subject != d.Subject {
		t.Fatalf("subject=%q", got.Subject)
	}

	if _, ok := s.GetByID("missing"); ok {
		t.Fatal("unexpected hit")
	}

	list := s.List()
	if len(list) != 1 {
		t.Fatalf("list len=%d", len(list))
	}
}

func TestDeviceStore_Revoke(t *testing.T) {
	dir := t.TempDir()
	s, _ := newDeviceStore(filepath.Join(dir, "devices.json"))

	now := time.Now().UTC()
	_ = s.Add(Device{DeviceID: "d1", Subject: "u@h", Org: "o", IssuedAt: now, ExpiresAt: now.Add(time.Hour)})

	if err := s.Revoke("d1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	got, _ := s.GetByID("d1")
	if !got.Revoked || got.RevokedAt == nil {
		t.Fatal("not revoked")
	}
	// Idempotent
	if err := s.Revoke("d1"); err != nil {
		t.Fatalf("re-revoke: %v", err)
	}

	if err := s.Revoke("missing"); err != ErrDeviceNotFound {
		t.Fatalf("revoke missing err=%v", err)
	}
}

func TestDeviceStore_TouchLastSeen(t *testing.T) {
	dir := t.TempDir()
	s, _ := newDeviceStore(filepath.Join(dir, "devices.json"))
	now := time.Now().UTC()
	_ = s.Add(Device{DeviceID: "d1", IssuedAt: now, ExpiresAt: now.Add(time.Hour)})

	stamp := now.Add(time.Minute)
	if err := s.TouchLastSeen("d1", stamp); err != nil {
		t.Fatalf("TouchLastSeen: %v", err)
	}
	got, _ := s.GetByID("d1")
	if got.LastSeen == nil || !got.LastSeen.Equal(stamp.UTC()) {
		t.Fatalf("last_seen=%v want=%v", got.LastSeen, stamp.UTC())
	}
}

func TestDeviceStore_RevokePushesToCRL(t *testing.T) {
	dir := t.TempDir()
	ds, _ := newDeviceStore(filepath.Join(dir, "devices.json"))
	crl, _ := newCRLStore(filepath.Join(dir, "revoked-serials.json"))
	ds.SetCRL(crl)

	now := time.Now().UTC()
	_ = ds.Add(Device{
		DeviceID:  "d1",
		Subject:   "alice@WIN-042",
		Org:       "acme",
		SerialHex: "0a1b2c",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	})

	if err := ds.Revoke("d1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !crl.Has("0a1b2c") {
		t.Fatal("CRL did not gain serial")
	}
	got, _ := ds.GetByID("d1")
	if !got.Revoked {
		t.Fatal("device not flagged revoked")
	}

	// Idempotent on the device side AND CRL side.
	if err := ds.Revoke("d1"); err != nil {
		t.Fatalf("re-revoke: %v", err)
	}
	if entries := crl.List(); len(entries) != 1 {
		t.Fatalf("CRL grew on re-revoke: %d entries", len(entries))
	}
}

func TestDeviceStore_RevokeWithoutCRL(t *testing.T) {
	// Backwards compat: a DeviceStore without a wired CRL still revokes
	// the device record, just without CRL push.
	dir := t.TempDir()
	ds, _ := newDeviceStore(filepath.Join(dir, "devices.json"))
	now := time.Now().UTC()
	_ = ds.Add(Device{DeviceID: "d1", SerialHex: "ab", IssuedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err := ds.Revoke("d1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	got, _ := ds.GetByID("d1")
	if !got.Revoked {
		t.Fatal("device not revoked")
	}
}

func TestDeviceStore_RevokeWithEmptySerialSkipsCRL(t *testing.T) {
	// If a device record has no serial_hex (e.g. legacy entry), Revoke must
	// still succeed and not push a bogus empty entry into the CRL.
	dir := t.TempDir()
	ds, _ := newDeviceStore(filepath.Join(dir, "devices.json"))
	crl, _ := newCRLStore(filepath.Join(dir, "revoked-serials.json"))
	ds.SetCRL(crl)
	now := time.Now().UTC()
	_ = ds.Add(Device{DeviceID: "legacy", IssuedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err := ds.Revoke("legacy"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if got := crl.List(); len(got) != 0 {
		t.Fatalf("CRL gained an entry for empty-serial device: %+v", got)
	}
}

func TestDeviceStore_UnRevokeRemovesFromCRL(t *testing.T) {
	dir := t.TempDir()
	ds, _ := newDeviceStore(filepath.Join(dir, "devices.json"))
	crl, _ := newCRLStore(filepath.Join(dir, "revoked-serials.json"))
	ds.SetCRL(crl)

	now := time.Now().UTC()
	_ = ds.Add(Device{
		DeviceID:  "d1",
		SerialHex: "cafe",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	})
	if err := ds.Revoke("d1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !crl.Has("cafe") {
		t.Fatal("expected serial in CRL")
	}
	if err := ds.UnRevoke("d1"); err != nil {
		t.Fatalf("UnRevoke: %v", err)
	}
	if crl.Has("cafe") {
		t.Fatal("CRL still contains serial after UnRevoke")
	}
	got, _ := ds.GetByID("d1")
	if got.Revoked {
		t.Fatal("device still flagged revoked after UnRevoke")
	}
	if got.RevokedAt != nil {
		t.Fatal("revoked_at not cleared")
	}

	// Idempotent
	if err := ds.UnRevoke("d1"); err != nil {
		t.Fatalf("UnRevoke twice: %v", err)
	}
	if err := ds.UnRevoke("missing"); err != ErrDeviceNotFound {
		t.Fatalf("UnRevoke missing err=%v", err)
	}
}

func TestDeviceStore_PicksUpExternalWrites(t *testing.T) {
	// Simulates tls-proxy writing devices.json while webui is running.
	dir := t.TempDir()
	path := filepath.Join(dir, "devices.json")
	s, err := newDeviceStore(path)
	if err != nil {
		t.Fatalf("newDeviceStore: %v", err)
	}
	if len(s.List()) != 0 {
		t.Fatal("expected empty list initially")
	}

	now := time.Now().UTC().Truncate(time.Second)
	external := []Device{{
		DeviceID:  "ext-1",
		Subject:   "bob@MAC-1",
		Org:       "acme",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}}
	data, _ := json.MarshalIndent(external, "", "  ")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("external write: %v", err)
	}

	// Revoke uses reload-before-write, so it should see the external record.
	if err := s.Revoke("ext-1"); err != nil {
		t.Fatalf("Revoke ext-1 (after external write): %v", err)
	}
	got, ok := s.GetByID("ext-1")
	if !ok {
		t.Fatal("ext-1 missing")
	}
	if !got.Revoked {
		t.Fatal("ext-1 not revoked")
	}
}

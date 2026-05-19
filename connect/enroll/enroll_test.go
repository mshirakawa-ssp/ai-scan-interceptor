package enroll

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnsureKey_GeneratesAndReloads(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")

	k1, err := EnsureKey(keyPath)
	if err != nil {
		t.Fatalf("first EnsureKey: %v", err)
	}
	if k1 == nil || k1.N.BitLen() < 2000 {
		t.Fatalf("expected >= 2048-bit RSA key, got %d", k1.N.BitLen())
	}
	k2, err := EnsureKey(keyPath)
	if err != nil {
		t.Fatalf("second EnsureKey: %v", err)
	}
	if k1.D.Cmp(k2.D) != 0 {
		t.Fatal("key not stable across loads")
	}
}

func TestBuildCSR_StructureAndSubject(t *testing.T) {
	dir := t.TempDir()
	key, err := EnsureKey(filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	sub := SubjectInfo{OSUser: "alice", Hostname: "lab01", Org: "acme"}
	csrPEM, err := BuildCSR(key, sub)
	if err != nil {
		t.Fatalf("BuildCSR: %v", err)
	}
	if !strings.Contains(string(csrPEM), "BEGIN CERTIFICATE REQUEST") {
		t.Fatalf("CSR not PEM: %q", string(csrPEM))
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("pem.Decode returned nil")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature invalid: %v", err)
	}
	if csr.Subject.CommonName != "alice@lab01" {
		t.Errorf("CN = %q, want alice@lab01", csr.Subject.CommonName)
	}
	if len(csr.Subject.Organization) != 1 || csr.Subject.Organization[0] != "acme" {
		t.Errorf("O = %v, want [acme]", csr.Subject.Organization)
	}
	// Ensure the public key matches.
	pub, ok := csr.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.Cmp(key.N) != 0 {
		t.Errorf("CSR pubkey does not match private key")
	}
}

func TestBuildCSR_NoOrg(t *testing.T) {
	dir := t.TempDir()
	key, _ := EnsureKey(filepath.Join(dir, "key.pem"))
	csrPEM, err := BuildCSR(key, SubjectInfo{OSUser: "bob", Hostname: "h"})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(csr.Subject.Organization) != 0 {
		t.Errorf("Organization should be empty, got %v", csr.Subject.Organization)
	}
}

func TestShouldRenew(t *testing.T) {
	now := time.Now()
	cert := &x509.Certificate{
		NotBefore: now.Add(-72 * time.Hour),
		NotAfter:  now.Add(72 * time.Hour),
	}
	if ShouldRenew(cert, now.Add(-71*time.Hour)) {
		t.Error("should not renew at start of lifetime")
	}
	if !ShouldRenew(cert, now.Add(1*time.Hour)) {
		t.Error("should renew past 50% lifetime")
	}
}

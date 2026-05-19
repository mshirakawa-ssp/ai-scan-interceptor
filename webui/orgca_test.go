package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestOrgCA_GenerateAndReload(t *testing.T) {
	dir := t.TempDir()

	ca1, err := newOrgCA(dir, "acme")
	if err != nil {
		t.Fatalf("first newOrgCA: %v", err)
	}
	if got := ca1.Subject(); got == "" {
		t.Fatal("subject empty after generate")
	}
	if ca1.NotAfter().IsZero() {
		t.Fatal("not_after zero")
	}
	if fp := ca1.Fingerprint(); len(fp) < 47 { // 32 bytes * 2 hex + 31 colons = 95 — at least > 47
		t.Fatalf("fingerprint suspiciously short: %q", fp)
	}

	// Files exist with 0600.
	for _, name := range []string{"org-ca.pem", "org-ca.key"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		mode := info.Mode().Perm()
		if mode != 0600 {
			t.Fatalf("%s perm=%o want 0600", name, mode)
		}
	}

	// Cert PEM parses to a CA.
	block, _ := pem.Decode(ca1.CertPEM())
	if block == nil {
		t.Fatal("cert pem did not decode")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if !cert.IsCA {
		t.Fatal("cert IsCA=false")
	}
	if cert.Subject.CommonName != "AI-Scan-Interceptor Org CA" {
		t.Fatalf("CN=%q", cert.Subject.CommonName)
	}
	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != "acme" {
		t.Fatalf("org=%v", cert.Subject.Organization)
	}

	// Reload: a second newOrgCA on the same dir must reuse the existing files.
	ca2, err := newOrgCA(dir, "different-org-ignored-on-reload")
	if err != nil {
		t.Fatalf("second newOrgCA: %v", err)
	}
	if string(ca1.CertPEM()) != string(ca2.CertPEM()) {
		t.Fatal("cert PEM changed across reload")
	}
	if ca1.Fingerprint() != ca2.Fingerprint() {
		t.Fatal("fingerprint changed across reload")
	}
}

func TestOrgCA_DefaultOrgName(t *testing.T) {
	dir := t.TempDir()
	ca, err := newOrgCA(dir, "")
	if err != nil {
		t.Fatalf("newOrgCA: %v", err)
	}
	block, _ := pem.Decode(ca.CertPEM())
	cert, _ := x509.ParseCertificate(block.Bytes)
	if cert.Subject.Organization[0] != "default-org" {
		t.Fatalf("org=%v", cert.Subject.Organization)
	}
}

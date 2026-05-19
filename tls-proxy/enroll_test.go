package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateTestCA produces a self-signed RSA CA suitable for use as the
// org CA in unit tests.
func generateTestCA(t *testing.T) (caCert *x509.Certificate, caKey *rsa.PrivateKey, caPEM []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-org-ca", Organization: []string{"test-org"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return cert, priv, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// generateTestCSR produces a CSR signed by a fresh RSA keypair.
func generateTestCSR(t *testing.T, cn string) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// TestSignCSR exercises the signing path directly: the org CA mints a cert
// for a CSR, and the resulting cert verifies against the CA pool.
func TestSignCSR(t *testing.T) {
	caCert, caKey, caPEM := generateTestCA(t)
	cfg := &enrollConfig{
		OrgCACert:    caCert,
		OrgCAKey:     caKey,
		OrgCAPEM:     caPEM,
		CertLifetime: 7 * 24 * time.Hour,
	}
	csrPEM := generateTestCSR(t, "alice@laptop")
	csr, err := parseCSRPEM(csrPEM)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	subject := pkix.Name{CommonName: "alice@laptop", Organization: []string{"acme"}}

	certPEM, expiresAt, serial, err := signCSR(cfg, csr, subject)
	if err != nil {
		t.Fatalf("signCSR: %v", err)
	}
	if serial == nil || serial.Sign() <= 0 {
		t.Fatalf("signCSR returned non-positive serial: %v", serial)
	}
	if !time.Now().Before(expiresAt) {
		t.Fatalf("expiresAt should be in the future, got %s", expiresAt)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatalf("output is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if leaf.Subject.CommonName != "alice@laptop" {
		t.Errorf("CN: want alice@laptop, got %q", leaf.Subject.CommonName)
	}
	if len(leaf.Subject.Organization) == 0 || leaf.Subject.Organization[0] != "acme" {
		t.Errorf("O: want [acme], got %v", leaf.Subject.Organization)
	}
	// Verify the cert chains back to the org CA.
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestEnrollHandler runs the full /enroll HTTP path end-to-end including
// token consumption and the second-call rejection.
func TestEnrollHandler(t *testing.T) {
	dir := t.TempDir()
	tokensPath := filepath.Join(dir, "enroll-tokens.json")
	caCert, caKey, caPEM := generateTestCA(t)

	// Seed one valid token.
	store := &enrollTokenStore{Tokens: []enrollToken{{
		Token:     "tok-valid-1",
		OrgID:     "acme",
		User:      "alice@laptop",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}}}
	if err := writeTokenStore(tokensPath, store); err != nil {
		t.Fatalf("seed tokens: %v", err)
	}

	cfg := &enrollConfig{
		Listen:         ":0",
		OrgCACert:      caCert,
		OrgCAKey:       caKey,
		OrgCAPEM:       caPEM,
		TokensFile:     tokensPath,
		TokensLockFile: tokensPath + ".lock",
		LockTimeout:    2 * time.Second,
		CertLifetime:   7 * 24 * time.Hour,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleEnroll(cfg, w, r)
	}))
	defer srv.Close()

	csrPEM := generateTestCSR(t, "anyone@anywhere")
	body, _ := json.Marshal(enrollRequest{CSR: csrPEM, EnrollmentToken: "tok-valid-1"})

	// First call: should succeed.
	resp, err := http.Post(srv.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	if resp.StatusCode != 200 {
		buf, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, buf)
	}
	var er enrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		t.Fatalf("decode: %v", err)
	}
	resp.Body.Close()
	if er.Cert == "" || er.CAChain == "" {
		t.Fatalf("empty cert/ca_chain in response: %+v", er)
	}
	block, _ := pem.Decode([]byte(er.Cert))
	if block == nil {
		t.Fatalf("issued cert not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	if leaf.Subject.CommonName != "alice@laptop" {
		t.Errorf("CN should be from token (alice@laptop), got %q", leaf.Subject.CommonName)
	}
	if len(leaf.Subject.Organization) == 0 || leaf.Subject.Organization[0] != "acme" {
		t.Errorf("O should be acme, got %v", leaf.Subject.Organization)
	}

	// Second call with same token: should be rejected (already consumed).
	resp2, err := http.Post(srv.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post 2: %v", err)
	}
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 on reuse, got %d", resp2.StatusCode)
	}
	resp2.Body.Close()

	// Unknown token: 401.
	body2, _ := json.Marshal(enrollRequest{CSR: csrPEM, EnrollmentToken: "tok-not-real"})
	resp3, err := http.Post(srv.URL, "application/json", bytes.NewReader(body2))
	if err != nil {
		t.Fatalf("post 3: %v", err)
	}
	if resp3.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 unknown token, got %d", resp3.StatusCode)
	}
	resp3.Body.Close()

	// Sanity: GET should be 405.
	resp4, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if resp4.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 on GET, got %d", resp4.StatusCode)
	}
	resp4.Body.Close()
}

// TestExpiredToken ensures expired tokens are rejected and not consumed.
func TestExpiredToken(t *testing.T) {
	dir := t.TempDir()
	tokensPath := filepath.Join(dir, "tokens.json")
	store := &enrollTokenStore{Tokens: []enrollToken{{
		Token:     "old",
		OrgID:     "acme",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}}}
	if err := writeTokenStore(tokensPath, store); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cfg := &enrollConfig{
		TokensFile:     tokensPath,
		TokensLockFile: tokensPath + ".lock",
		LockTimeout:    2 * time.Second,
	}
	if _, err := consumeEnrollToken(cfg, "old"); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

// TestIdentityFromCert validates that CN/O extraction works.
func TestIdentityFromCert(t *testing.T) {
	caCert, caKey, _ := generateTestCA(t)
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "bob@desktop", Organization: []string{"contoso"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &priv.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	leaf, _ := x509.ParseCertificate(der)
	id := identityFromCert(leaf)
	if id.UserHost != "bob@desktop" {
		t.Errorf("UserHost: want bob@desktop, got %q", id.UserHost)
	}
	if id.OrgID != "contoso" {
		t.Errorf("OrgID: want contoso, got %q", id.OrgID)
	}
	if id.Serial == "" {
		t.Errorf("Serial empty")
	}
}

// quick self-check on parsing helper.
func TestParseCSRPEMRejectsNonCSR(t *testing.T) {
	bogus := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("nope")})
	if _, err := parseCSRPEM(string(bogus)); err == nil {
		t.Fatal("expected error for non-CSR PEM")
	}
	if _, err := parseCSRPEM(""); err == nil {
		t.Fatal("expected error for empty")
	}
}

// Ensure os.ReadFile works for our token paths even when the file is absent.
func TestReadTokenStoreMissing(t *testing.T) {
	dir := t.TempDir()
	store, err := readTokenStore(filepath.Join(dir, "nope.json"))
	if err != nil {
		t.Fatalf("err on missing: %v", err)
	}
	if len(store.Tokens) != 0 {
		t.Errorf("want empty, got %d", len(store.Tokens))
	}
}

// TestEnrollWritesDevice verifies the integration with /config/devices.json:
// after a successful enrollment, the device record exists with all the
// fields the webui's revoke flow needs (subject, org, serial_hex,
// expires_at, revoked=false). This is the end of the chain that closes the
// CRL gap — without this, webui's Revoke would have an empty SerialHex.
func TestEnrollWritesDevice(t *testing.T) {
	dir := t.TempDir()
	tokensPath := filepath.Join(dir, "enroll-tokens.json")
	devicesPath := filepath.Join(dir, "devices.json")
	caCert, caKey, caPEM := generateTestCA(t)

	store := &enrollTokenStore{Tokens: []enrollToken{{
		Token:     "tok-dev-1",
		OrgID:     "acme",
		User:      "alice@laptop",
		ExpiresAt: time.Now().Add(time.Hour),
	}}}
	if err := writeTokenStore(tokensPath, store); err != nil {
		t.Fatalf("seed tokens: %v", err)
	}

	cfg := &enrollConfig{
		Listen:          ":0",
		OrgCACert:       caCert,
		OrgCAKey:        caKey,
		OrgCAPEM:        caPEM,
		TokensFile:      tokensPath,
		TokensLockFile:  tokensPath + ".lock",
		DevicesFile:     devicesPath,
		DevicesLockFile: devicesPath + ".lock",
		LockTimeout:     2 * time.Second,
		CertLifetime:    7 * 24 * time.Hour,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleEnroll(cfg, w, r)
	}))
	defer srv.Close()

	csrPEM := generateTestCSR(t, "anyone@anywhere")
	body, _ := json.Marshal(enrollRequest{CSR: csrPEM, EnrollmentToken: "tok-dev-1"})

	resp, err := http.Post(srv.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	if resp.StatusCode != 200 {
		buf, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, buf)
	}
	var er enrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		t.Fatalf("decode: %v", err)
	}
	resp.Body.Close()

	// Pull the issued cert's serial — that is what must end up in
	// devices.json.SerialHex.
	block, _ := pem.Decode([]byte(er.Cert))
	if block == nil {
		t.Fatal("issued cert not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	wantSerial := normalizeSerialHex(leaf.SerialNumber.Text(16))

	// Read devices.json and assert the appended record matches.
	devs, err := readDevicesFile(devicesPath)
	if err != nil {
		t.Fatalf("read devices: %v", err)
	}
	if len(devs) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devs))
	}
	d := devs[0]
	if d.DeviceID == "" {
		t.Error("DeviceID empty")
	}
	if d.Subject != "alice@laptop" {
		t.Errorf("Subject: want alice@laptop, got %q", d.Subject)
	}
	if d.Org != "acme" {
		t.Errorf("Org: want acme, got %q", d.Org)
	}
	if d.SerialHex != wantSerial {
		t.Errorf("SerialHex: want %s, got %s", wantSerial, d.SerialHex)
	}
	if d.SerialHex == "" {
		t.Error("SerialHex must not be empty (webui CRL push depends on it)")
	}
	if d.Revoked {
		t.Error("new device should not be revoked")
	}
	if d.RevokedAt != nil {
		t.Error("RevokedAt should be nil for new device")
	}
	if d.IssuedAt.IsZero() {
		t.Error("IssuedAt must be set")
	}
	if d.ExpiresAt.IsZero() || !d.ExpiresAt.After(d.IssuedAt) {
		t.Errorf("ExpiresAt must be after IssuedAt; got issued=%s expires=%s", d.IssuedAt, d.ExpiresAt)
	}

	// On-disk file format: must be a JSON array of objects so the webui's
	// devicestore can parse it directly.
	raw, err := os.ReadFile(devicesPath)
	if err != nil {
		t.Fatalf("read raw: %v", err)
	}
	var arr []map[string]any
	if err := json.Unmarshal(raw, &arr); err != nil {
		t.Fatalf("file must be JSON array of objects: %v\nbody: %s", err, raw)
	}
	if len(arr) != 1 {
		t.Fatalf("array length want 1, got %d", len(arr))
	}
	requiredKeys := []string{"device_id", "subject", "org", "serial_hex", "issued_at", "expires_at", "revoked"}
	for _, k := range requiredKeys {
		if _, ok := arr[0][k]; !ok {
			t.Errorf("device JSON missing required key %q (raw=%s)", k, raw)
		}
	}

	// File should be 0600 since we are persisting cert metadata.
	info, err := os.Stat(devicesPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("devices.json perm: want 0600, got %o", info.Mode().Perm())
	}
}

// TestAppendDeviceRejectsDuplicateID covers the unlikely-but-defended
// duplicate device_id case. We exercise appendDevice directly with a
// pre-seeded file because real UUID collisions never happen in practice.
func TestAppendDeviceRejectsDuplicateID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "devices.json")
	lock := path + ".lock"

	d := device{
		DeviceID:  "fixed-id",
		Subject:   "alice@laptop",
		Org:       "acme",
		SerialHex: "abc123",
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	if err := appendDevice(path, lock, time.Second, d); err != nil {
		t.Fatalf("first append: %v", err)
	}
	// Same DeviceID -> should be rejected.
	d2 := d
	d2.SerialHex = "different"
	if err := appendDevice(path, lock, time.Second, d2); err == nil {
		t.Fatal("expected error on duplicate device_id, got nil")
	} else if !errors.Is(err, errDeviceIDExists) {
		t.Fatalf("expected errDeviceIDExists, got %v", err)
	}
	// Different DeviceID -> should succeed.
	d3 := d
	d3.DeviceID = "another-id"
	if err := appendDevice(path, lock, time.Second, d3); err != nil {
		t.Fatalf("third append: %v", err)
	}

	devs, err := readDevicesFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(devs) != 2 {
		t.Errorf("expected 2 devices, got %d", len(devs))
	}
}

// TestNewDeviceIDFormat sanity-checks the UUIDv4 shape we generate.
func TestNewDeviceIDFormat(t *testing.T) {
	id, err := newDeviceID()
	if err != nil {
		t.Fatalf("newDeviceID: %v", err)
	}
	// 8-4-4-4-12 hex = 36 chars
	if len(id) != 36 {
		t.Errorf("len: want 36, got %d (%q)", len(id), id)
	}
	// Version nibble (position 14, 0-indexed) must be '4'.
	if id[14] != '4' {
		t.Errorf("version nibble: want 4, got %c (%q)", id[14], id)
	}
	// Variant nibble (position 19) must be one of 8,9,a,b.
	switch id[19] {
	case '8', '9', 'a', 'b':
	default:
		t.Errorf("variant nibble: want one of 8,9,a,b, got %c (%q)", id[19], id)
	}
	// Two consecutive calls must differ.
	id2, _ := newDeviceID()
	if id == id2 {
		t.Error("two calls produced the same id")
	}
}

// keep go.mod stable: compile-time reference to unused symbols not yet wired.
var _ = fmt.Sprintf
var _ = os.Getenv

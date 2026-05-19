package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// orgCAKeyBits is the RSA key size for the organization CA. 4096 bits matches
// modern best-practice for long-lived signing CAs.
const orgCAKeyBits = 4096

// orgCAValidYears is how many years the self-signed organization CA stays valid.
const orgCAValidYears = 10

// OrgCA wraps the auto-generated organization root CA used to sign device
// certificates issued by the tls-proxy /enroll endpoint.
//
// On startup, if /config/org-ca.pem and /config/org-ca.key both exist they are
// loaded; otherwise a new self-signed CA is generated and persisted with 0600
// permissions. The same files are mounted into the tls-proxy container.
type OrgCA struct {
	mu sync.RWMutex

	certPath string
	keyPath  string
	orgName  string

	certPEM []byte
	keyPEM  []byte

	cert *x509.Certificate
	key  *rsa.PrivateKey
}

// newOrgCA loads an existing CA from configDir or generates a new one.
// orgName seeds the Organization field of the CA subject; it is purely
// informational and stable across restarts once written.
func newOrgCA(configDir, orgName string) (*OrgCA, error) {
	if orgName == "" {
		orgName = "default-org"
	}
	o := &OrgCA{
		certPath: filepath.Join(configDir, "org-ca.pem"),
		keyPath:  filepath.Join(configDir, "org-ca.key"),
		orgName:  orgName,
	}
	loaded, err := o.load()
	if err != nil {
		return nil, fmt.Errorf("load org CA: %w", err)
	}
	if loaded {
		return o, nil
	}
	if err := o.generate(); err != nil {
		return nil, fmt.Errorf("generate org CA: %w", err)
	}
	return o, nil
}

// load attempts to read existing CA cert+key. Returns (false, nil) if either
// file is missing — the caller should generate a fresh CA in that case.
func (o *OrgCA) load() (bool, error) {
	certData, err := os.ReadFile(o.certPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	keyData, err := os.ReadFile(o.keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	certBlock, _ := pem.Decode(certData)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return false, errors.New("org-ca.pem: not a PEM CERTIFICATE")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return false, fmt.Errorf("parse org CA cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return false, errors.New("org-ca.key: not a PEM block")
	}
	var key *rsa.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		// PKCS#8
		anyKey, errParse := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if errParse != nil {
			return false, fmt.Errorf("parse org CA key (PKCS8): %w", errParse)
		}
		var ok bool
		key, ok = anyKey.(*rsa.PrivateKey)
		if !ok {
			return false, errors.New("org-ca.key: not an RSA key")
		}
	default:
		return false, fmt.Errorf("org-ca.key: unsupported PEM type %q", keyBlock.Type)
	}
	if err != nil {
		return false, fmt.Errorf("parse org CA key: %w", err)
	}
	o.certPEM = certData
	o.keyPEM = keyData
	o.cert = cert
	o.key = key
	return true, nil
}

// generate creates a fresh self-signed CA and persists it atomically.
func (o *OrgCA) generate() error {
	key, err := rsa.GenerateKey(rand.Reader, orgCAKeyBits)
	if err != nil {
		return fmt.Errorf("rsa generate: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("serial: %w", err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "AI-Scan-Interceptor Org CA",
			Organization: []string{o.orgName},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(orgCAValidYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	if err := atomicWrite(o.certPath, certPEM, 0600); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := atomicWrite(o.keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("parse generated cert: %w", err)
	}
	o.certPEM = certPEM
	o.keyPEM = keyPEM
	o.cert = cert
	o.key = key
	return nil
}

// CertPEM returns the PEM-encoded CA certificate (safe to expose publicly).
func (o *OrgCA) CertPEM() []byte {
	o.mu.RLock()
	defer o.mu.RUnlock()
	out := make([]byte, len(o.certPEM))
	copy(out, o.certPEM)
	return out
}

// Subject returns a human-readable description of the CA subject for the UI.
func (o *OrgCA) Subject() string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.cert == nil {
		return ""
	}
	return o.cert.Subject.String()
}

// NotAfter returns the CA expiration timestamp.
func (o *OrgCA) NotAfter() time.Time {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.cert == nil {
		return time.Time{}
	}
	return o.cert.NotAfter
}

// Fingerprint returns the SHA-256 fingerprint as a colon-separated hex string,
// useful to display in the UI for verification.
func (o *OrgCA) Fingerprint() string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.cert == nil {
		return ""
	}
	sum := sha256Sum(o.cert.Raw)
	return colonHex(sum[:])
}

// sha256Sum is a small wrapper for clarity; returns the SHA-256 digest of b.
func sha256Sum(b []byte) [sha256.Size]byte {
	return sha256.Sum256(b)
}

// colonHex formats a byte slice as upper-case hex separated by colons,
// e.g. "AB:CD:EF". Used for cert fingerprint display.
func colonHex(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = strings.ToUpper(hex.EncodeToString([]byte{x}))
	}
	return strings.Join(parts, ":")
}

// atomicWrite writes data to path via a temp file + rename, with mode set on the
// temp file before rename so the published file never exists with looser perms.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

// Package enroll implements client-cert enrollment and renewal:
// generate (or load) an RSA keypair, build a CSR, POST it to the
// interceptor /enroll endpoint, and persist the returned cert.
package enroll

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"ai-scan-connect/config"
)

const (
	keyFileName  = "client.key"
	certFileName = "cert.pem"
	csrFileName  = "client.csr" // kept for debugging; not strictly required
)

// Paths returns the absolute paths to the key and cert files for this host.
type Paths struct {
	StateDir string
	KeyPath  string
	CertPath string
}

// DefaultPaths returns the standard on-disk paths under DefaultStateDir.
func DefaultPaths() Paths {
	dir := config.DefaultStateDir()
	return Paths{
		StateDir: dir,
		KeyPath:  filepath.Join(dir, keyFileName),
		CertPath: filepath.Join(dir, certFileName),
	}
}

// EnsureKey loads the RSA key from path, or generates and persists a new one.
// Permissions are 0600.
func EnsureKey(path string) (*rsa.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("enroll: %s is not PEM", path)
		}
		// Try PKCS8 then PKCS1.
		if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			rk, ok := k.(*rsa.PrivateKey)
			if !ok {
				return nil, errors.New("enroll: stored key is not RSA")
			}
			return rk, nil
		}
		if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return k, nil
		}
		return nil, fmt.Errorf("enroll: cannot parse key %s", path)
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("enroll: rsa keygen: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := writeFile0600(path, pemBytes); err != nil {
		return nil, err
	}
	return key, nil
}

// SubjectInfo describes the CN/O used in the CSR.
type SubjectInfo struct {
	OSUser   string // e.g. "alice"
	Hostname string // e.g. "alice-mbp"
	Org      string // e.g. "acme"
}

// CurrentSubject derives a SubjectInfo from the running OS context.
func CurrentSubject(org string) (SubjectInfo, error) {
	u, err := user.Current()
	if err != nil {
		return SubjectInfo{}, err
	}
	host, err := os.Hostname()
	if err != nil {
		return SubjectInfo{}, err
	}
	return SubjectInfo{
		OSUser:   u.Username,
		Hostname: host,
		Org:      org,
	}, nil
}

// BuildCSR creates a PEM-encoded CSR for the given key and subject.
func BuildCSR(key *rsa.PrivateKey, sub SubjectInfo) ([]byte, error) {
	cn := fmt.Sprintf("%s@%s", sub.OSUser, sub.Hostname)
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: nonEmptyOrgs(sub.Org),
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("enroll: CreateCertificateRequest: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func nonEmptyOrgs(org string) []string {
	if org == "" {
		return nil
	}
	return []string{org}
}

// EnrollRequest is the JSON body sent to the /enroll endpoint.
type EnrollRequest struct {
	Token   string `json:"token"`             // one-time enrollment token
	CSR     string `json:"csr"`               // PEM-encoded CSR
	Host    string `json:"hostname,omitempty"`
	OSUser  string `json:"os_user,omitempty"`
}

// EnrollResponse is the JSON returned by the /enroll endpoint.
type EnrollResponse struct {
	CertPEM string `json:"cert_pem"`
	// The CA chain may also be returned; we ignore unknown fields.
}

// Enroll posts a CSR to the configured enroll URL and persists the resulting cert.
//
// httpClient is optional; if nil, a default client trusting only the org CA is built.
func Enroll(cfg *config.Config, paths Paths, httpClient *http.Client) error {
	key, err := EnsureKey(paths.KeyPath)
	if err != nil {
		return err
	}
	sub, err := CurrentSubject(cfg.Org)
	if err != nil {
		return err
	}
	csrPEM, err := BuildCSR(key, sub)
	if err != nil {
		return err
	}
	// Stash CSR for debugging (best-effort).
	_ = writeFile0600(filepath.Join(paths.StateDir, csrFileName), csrPEM)

	if httpClient == nil {
		httpClient, err = buildEnrollClient(cfg.OrgCAPEM)
		if err != nil {
			return err
		}
	}

	body := EnrollRequest{
		Token:  cfg.EnrollmentToken,
		CSR:    string(csrPEM),
		Host:   sub.Hostname,
		OSUser: sub.OSUser,
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, cfg.EnrollURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ai-scan-connect/0.1")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("enroll: POST %s: %w", cfg.EnrollURL, err)
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("enroll: server returned %d: %s", resp.StatusCode, string(respBytes))
	}

	var er EnrollResponse
	if err := json.Unmarshal(respBytes, &er); err != nil {
		return fmt.Errorf("enroll: bad response: %w", err)
	}
	if er.CertPEM == "" {
		return errors.New("enroll: empty cert_pem in response")
	}
	if err := writeFile0600(paths.CertPath, []byte(er.CertPEM)); err != nil {
		return err
	}
	return nil
}

// buildEnrollClient returns an http.Client that trusts only the org CA.
func buildEnrollClient(caPEM string) (*http.Client, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, errors.New("enroll: invalid org_ca_pem")
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		},
	}
	return &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}, nil
}

func writeFile0600(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// LoadCert reads and parses the persisted client certificate.
func LoadCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("enroll: %s is not PEM", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

// ShouldRenew reports whether cert is past 50% of its lifetime.
func ShouldRenew(cert *x509.Certificate, now time.Time) bool {
	total := cert.NotAfter.Sub(cert.NotBefore)
	if total <= 0 {
		return true
	}
	half := cert.NotBefore.Add(total / 2)
	return now.After(half)
}

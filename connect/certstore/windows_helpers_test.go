package certstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestPemFirstCert_PicksCertificateBlock(t *testing.T) {
	// Generate a self-signed cert and surround it with junk + a non-CERT PEM block.
	der := selfSignedDER(t, "test-ca")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	junkPEM := pem.EncodeToMemory(&pem.Block{Type: "OTHER", Bytes: []byte("xx")})
	combined := append([]byte("# garbage line\n"), append(junkPEM, certPEM...)...)

	c, err := pemFirstCert(combined)
	if err != nil {
		t.Fatalf("pemFirstCert: %v", err)
	}
	if c.Subject.CommonName != "test-ca" {
		t.Errorf("CN = %q, want test-ca", c.Subject.CommonName)
	}
}

func TestPemFirstCert_NoBlockReturnsError(t *testing.T) {
	if _, err := pemFirstCert([]byte("not pem")); err == nil {
		t.Fatal("expected error on missing PEM")
	}
}

func TestSha1Hex_KnownValue(t *testing.T) {
	// echo -n "abc" | sha1sum -> a9993e364706816aba3e25717850c26c9cd0d89d
	got := sha1Hex([]byte("abc"))
	want := "A9993E364706816ABA3E25717850C26C9CD0D89D"
	if got != want {
		t.Errorf("sha1Hex(abc) = %q, want %q", got, want)
	}
}

func TestCertutilAddArgs(t *testing.T) {
	args := certutilAddArgs(`C:\tmp\ca.pem`)
	if len(args) != 4 {
		t.Fatalf("expected 4 args, got %d (%v)", len(args), args)
	}
	if args[0] != "-addstore" || args[1] != "-f" || args[2] != "Root" {
		t.Errorf("unexpected args: %v", args)
	}
	if !strings.HasSuffix(args[3], "ca.pem") {
		t.Errorf("path arg lost: %v", args)
	}
}

func TestCertutilDelArgs(t *testing.T) {
	args := certutilDelArgs("ABCD1234")
	if len(args) != 3 || args[0] != "-delstore" || args[1] != "Root" || args[2] != "ABCD1234" {
		t.Errorf("unexpected args: %v", args)
	}
}

func TestCertutilStoreArgs(t *testing.T) {
	args := certutilStoreArgs("ABCD1234")
	if args[0] != "-store" || args[1] != "Root" || args[2] != "ABCD1234" {
		t.Errorf("unexpected args: %v", args)
	}
}

// selfSignedDER returns a freshly-generated self-signed cert in DER form.
func selfSignedDER(t *testing.T, cn string) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

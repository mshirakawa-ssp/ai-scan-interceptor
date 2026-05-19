package certstore

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
)

// These helpers are pure and used by the Windows installer. They live in a
// non-tagged file so they can be unit-tested on any host (Linux CI included).

// pemFirstCert returns the first CERTIFICATE block as an *x509.Certificate.
func pemFirstCert(pemBytes []byte) (*x509.Certificate, error) {
	rest := pemBytes
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			return nil, errors.New("no CERTIFICATE block in PEM")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
		rest = r
	}
}

// sha1Hex returns the uppercase hex SHA-1 of raw.
func sha1Hex(raw []byte) string {
	sum := sha1.Sum(raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// certutilAddArgs returns the args for `certutil -addstore -f Root <path>`.
func certutilAddArgs(pemPath string) []string {
	return []string{"-addstore", "-f", "Root", pemPath}
}

// certutilDelArgs returns the args for `certutil -delstore Root <thumbprint>`.
func certutilDelArgs(thumbprint string) []string {
	return []string{"-delstore", "Root", thumbprint}
}

// certutilStoreArgs returns args for `certutil -store Root <thumbprint>` (lookup).
func certutilStoreArgs(thumbprint string) []string {
	return []string{"-store", "Root", thumbprint}
}

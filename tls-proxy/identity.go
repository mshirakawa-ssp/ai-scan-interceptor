// identity.go: utilities for extracting client identity from a verified
// peer certificate (mTLS) or other transport-layer signals.
//
// The conventions used by AI-Scan-Connect when issuing CSRs:
//   Subject CommonName (CN): "user@host"  e.g. "alice@laptop-01"
//   Subject Organization (O): "<org-id>"   e.g. "acme-corp"
//
// These are emitted into LogEntry.UserID and LogEntry.IdentitySource so that
// downstream analysis can attribute traffic to the correct user/org.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
)

// PeerIdentity captures the parts of a verified client cert we care about.
type PeerIdentity struct {
	UserHost string // CN, expected form "user@host"
	OrgID    string // first O entry, may be ""
	Serial   string // hex-encoded cert serial, useful for revocation correlation
}

// HasUser reports whether a usable user@host is present.
func (p PeerIdentity) HasUser() bool {
	return p.UserHost != ""
}

// extractPeerIdentity inspects a TLS connection state populated by a
// successful mTLS handshake (ClientAuth=RequireAndVerifyClientCert) and
// returns the identity expressed by the leaf peer certificate.
// Returns the zero value if no peer cert is present.
func extractPeerIdentity(state tls.ConnectionState) PeerIdentity {
	if len(state.PeerCertificates) == 0 {
		return PeerIdentity{}
	}
	return identityFromCert(state.PeerCertificates[0])
}

// identityFromCert is the cert-only variant for testing and reuse.
func identityFromCert(cert *x509.Certificate) PeerIdentity {
	if cert == nil {
		return PeerIdentity{}
	}
	id := PeerIdentity{
		UserHost: strings.TrimSpace(cert.Subject.CommonName),
	}
	if len(cert.Subject.Organization) > 0 {
		id.OrgID = strings.TrimSpace(cert.Subject.Organization[0])
	}
	if cert.SerialNumber != nil {
		id.Serial = cert.SerialNumber.Text(16)
	}
	return id
}

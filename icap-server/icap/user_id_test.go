package icap

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func makeJWT(sub string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	claims, _ := json.Marshal(map[string]string{"sub": sub, "iss": "test"})
	payload := base64.RawURLEncoding.EncodeToString(claims)
	return header + "." + payload + ".fakesignature"
}

// TestExtractUserID_CertSubjectTakesPriority verifies that a present
// X-User-Cert-Subject header wins over hostname and JWT sub.
func TestExtractUserID_CertSubjectTakesPriority(t *testing.T) {
	id, src := extractUserID("CN=alice@corp.example", "test-host", "Bearer "+makeJWT("jwt-sub"))
	if id != "CN=alice@corp.example" {
		t.Errorf("want CN=alice@corp.example, got %q", id)
	}
	if src != "mtls-cert" {
		t.Errorf("want source=mtls-cert, got %q", src)
	}
}

// TestExtractUserID_HostnameTakesPriority verifies that the reverse-DNS hostname
// takes priority over the JWT sub claim when no cert subject is present.
func TestExtractUserID_HostnameTakesPriority(t *testing.T) {
	id, src := extractUserID("", "test-host", "Bearer "+makeJWT("jwt-sub"))
	if id != "test-host" {
		t.Errorf("want test-host, got %q", id)
	}
	if src != "reverse-dns" {
		t.Errorf("want source=reverse-dns, got %q", src)
	}
}

func TestExtractUserID_Hostname(t *testing.T) {
	id, src := extractUserID("", "alice-laptop", "")
	if id != "alice-laptop" {
		t.Errorf("want alice-laptop, got %q", id)
	}
	if src != "reverse-dns" {
		t.Errorf("want source=reverse-dns, got %q", src)
	}
}

func TestExtractUserID_JWT(t *testing.T) {
	id, src := extractUserID("", "", "Bearer "+makeJWT("carol@example.com"))
	if id != "carol@example.com" {
		t.Errorf("want carol@example.com, got %q", id)
	}
	if src != "jwt-sub" {
		t.Errorf("want source=jwt-sub, got %q", src)
	}
}

func TestExtractUserID_Empty(t *testing.T) {
	id, src := extractUserID("", "", "")
	if id != "" {
		t.Errorf("want empty, got %q", id)
	}
	if src != "ip-only" {
		t.Errorf("want source=ip-only, got %q", src)
	}
}

func TestExtractUserID_InvalidJWT(t *testing.T) {
	id, src := extractUserID("", "", "Bearer notajwt")
	if id != "" {
		t.Errorf("want empty for non-JWT, got %q", id)
	}
	if src != "ip-only" {
		t.Errorf("want source=ip-only for non-JWT, got %q", src)
	}
}

// TestExtractUserID_CertSubjectWhitespace verifies that a whitespace-only
// X-User-Cert-Subject header is ignored and we fall through to the next
// identity source.
func TestExtractUserID_CertSubjectWhitespace(t *testing.T) {
	id, src := extractUserID("   ", "alice-laptop", "")
	if id != "alice-laptop" {
		t.Errorf("want alice-laptop, got %q", id)
	}
	if src != "reverse-dns" {
		t.Errorf("want source=reverse-dns, got %q", src)
	}
}

func TestJWTSub_NotBearer(t *testing.T) {
	got := jwtSub("Basic dXNlcjpwYXNz")
	if got != "" {
		t.Errorf("want empty for Basic auth, got %q", got)
	}
}

func TestJWTSub_MissingSub(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"test"}`))
	token := strings.Join([]string{header, payload, "sig"}, ".")
	got := jwtSub("Bearer " + token)
	if got != "" {
		t.Errorf("want empty when sub missing, got %q", got)
	}
}

func TestLookupHostname_Loopback(t *testing.T) {
	// Loopback addresses should return empty (no useful identity)
	if got := lookupHostname("127.0.0.1"); got != "" {
		t.Errorf("loopback should return empty, got %q", got)
	}
	if got := lookupHostname("::1"); got != "" {
		t.Errorf("IPv6 loopback should return empty, got %q", got)
	}
}

func TestLookupHostname_Empty(t *testing.T) {
	if got := lookupHostname(""); got != "" {
		t.Errorf("empty IP should return empty, got %q", got)
	}
}

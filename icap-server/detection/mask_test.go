package detection

import (
	"bytes"
	"net/url"
	"strings"
	"testing"
)

func TestMaskSensitive_OpenAIKey(t *testing.T) {
	// sk-proj- prefix followed by 20+ alphanumeric chars matches CRED-001
	input := []byte("Here is my key: sk-proj-abc123xxxxxxxxxxxxxxxx end")
	got := MaskSensitive(input)
	if bytes.Contains(got, []byte("sk-proj-")) {
		t.Errorf("OpenAI key not redacted: %q", got)
	}
	if !bytes.Contains(got, []byte("[REDACTED]")) {
		t.Errorf("expected [REDACTED] in output: %q", got)
	}
}

func TestMaskSensitive_AnthropicKey(t *testing.T) {
	// sk-ant-api<2digits>- prefix followed by 20+ chars matches CRED-002
	input := []byte("key=sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456")
	got := MaskSensitive(input)
	if bytes.Contains(got, []byte("sk-ant-api03-")) {
		t.Errorf("Anthropic key not redacted: %q", got)
	}
	if !bytes.Contains(got, []byte("[REDACTED]")) {
		t.Errorf("expected [REDACTED] in output: %q", got)
	}
}

func TestMaskSensitive_AWSAccessKey(t *testing.T) {
	// AKIA prefix followed by exactly 16 uppercase alphanumeric chars matches CRED-003
	input := []byte("aws_access_key_id = AKIAIOSFODNN7EXAMPLE")
	got := MaskSensitive(input)
	if bytes.Contains(got, []byte("AKIAIOSFODNN7EXAMPLE")) {
		t.Errorf("AWS access key not redacted: %q", got)
	}
	if !bytes.Contains(got, []byte("[REDACTED]")) {
		t.Errorf("expected [REDACTED] in output: %q", got)
	}
}

func TestMaskSensitive_JWTToken(t *testing.T) {
	// eyJ<header>.eyJ<payload>.<sig> matches CRED-008
	// Both header and payload parts must be 10+ base64url chars after eyJ
	jwt := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature"
	input := []byte("Authorization: Bearer " + jwt)
	got := MaskSensitive(input)
	if bytes.Contains(got, []byte("eyJhbGciOiJSUzI1NiJ9")) {
		t.Errorf("JWT token not redacted: %q", got)
	}
	if !bytes.Contains(got, []byte("[REDACTED]")) {
		t.Errorf("expected [REDACTED] in output: %q", got)
	}
}

func TestMaskSensitive_AWSSecretKey_JSONQuoted(t *testing.T) {
	// export KEY="value" becomes KEY=\"value\" in JSON-encoded string
	input := []byte(`AWS_SECRET_ACCESS_KEY=\"wwb4NMO0srcMX6J67j2jWdadGZ6yKpSZyZKqEYPx\"`)
	got := MaskSensitive(input)
	if bytes.Contains(got, []byte("wwb4NMO")) {
		t.Errorf("AWS secret key value not redacted: %q", got)
	}
	if !bytes.Contains(got, []byte("[REDACTED]")) {
		t.Errorf("expected [REDACTED] in output: %q", got)
	}
	// Key name must be preserved (value-only masking).
	if !bytes.Contains(got, []byte("AWS_SECRET_ACCESS_KEY")) {
		t.Errorf("key name was over-redacted (should be preserved): %q", got)
	}
}

func TestMaskSensitive_AWSSessionToken_JSONQuoted(t *testing.T) {
	input := []byte(`AWS_SESSION_TOKEN=\"IQoJb3JpZ2luX2VjELL//////////wEaCXVzLWVhc3QtMSJIMEYCIQD0123456789abcdefghij==\"`)
	got := MaskSensitive(input)
	if bytes.Contains(got, []byte("IQoJb3JpZ2luX2Vj")) {
		t.Errorf("AWS session token value not redacted: %q", got)
	}
	if !bytes.Contains(got, []byte("[REDACTED]")) {
		t.Errorf("expected [REDACTED] in output: %q", got)
	}
	// Key name must be preserved.
	if !bytes.Contains(got, []byte("AWS_SESSION_TOKEN")) {
		t.Errorf("key name was over-redacted (should be preserved): %q", got)
	}
}

func TestMaskSensitive_NoMatch(t *testing.T) {
	// Plain text with no secrets should be returned unchanged
	input := []byte("Hello, how can I help you today? Let me search for information.")
	got := MaskSensitive(input)
	if !bytes.Equal(got, input) {
		t.Errorf("plain text modified unexpectedly: got %q, want %q", got, input)
	}
}

// --- MaskSensitiveForService tests ---

func initTestRules(t *testing.T) {
	t.Helper()
	entries := DefaultEntries()
	SetActiveRules(EntriesToAlertRules(entries))
}

// TestMaskForService_AnthropicJSON verifies that credentials embedded in a
// realistic Anthropic API JSON body are masked when using MaskSensitiveForService.
// This is the Claude Code path: content is an array of text parts with newline
// escapes, which broke raw-byte regex matching in the original MaskSensitive.
func TestMaskForService_AnthropicJSON(t *testing.T) {
	initTestRules(t)

	// Construct a body similar to what Claude Code SDK sends.
	// The session token is a realistic 300-char base64 blob (real tokens are 400-1000+).
	sessionToken := "FwoGZXIvYXdzEJr//////////wEaDmFzaWEtbm9ydGhlYXN0IiC9lKhxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=="
	body := []byte(`{"model":"claude-sonnet-4-5","max_tokens":8096,"messages":[{"role":"user","content":[{"type":"text","text":"テストなので何もしないで\nexport AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nexport AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nexport AWS_SESSION_TOKEN=` + sessionToken + `"}]}]}`)

	got := MaskSensitiveForService(body, "api.anthropic.com", "/v1/messages")

	for _, secret := range []string{"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI", "FwoGZXIvYXdz"} {
		if bytes.Contains(got, []byte(secret)) {
			t.Errorf("credential %q still present after masking;\nbody: %s", secret, got)
		}
	}
	if !bytes.Contains(got, []byte("[REDACTED]")) {
		t.Errorf("expected [REDACTED] in output:\n%s", got)
	}
}

// TestMaskForService_GeminiWeb verifies that credentials inside a Gemini-Web
// URL-encoded form body are masked. The raw body has percent-encoded characters
// (%3D for =, %2F for /) that defeat the raw-byte regex approach.
func TestMaskForService_GeminiWeb(t *testing.T) {
	initTestRules(t)

	// Build the nested Gemini-Web body structure.
	// Outer f.req: [null, "<payload_json>"]
	// Payload: [["<user_text>", null, null, null, null, null, null, ""], ...]
	userText := `export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`

	// Build the payload JSON as a Go string, then JSON-encode it as the inner string.
	// payload = [["<user_text>"]]
	payloadJSON := `[["` + strings.ReplaceAll(userText, "\n", `\n`) + `"]]`
	// Outer: [null, payloadJSON]
	// We need to JSON-encode payloadJSON as a string value.
	fReqJSON := `[null,"` + strings.ReplaceAll(strings.ReplaceAll(payloadJSON, `\`, `\\`), `"`, `\"`) + `"]`

	formBody := url.Values{}
	formBody.Set("f.req", fReqJSON)
	body := []byte(formBody.Encode())

	got := MaskSensitiveForService(body, "gemini.google.com", "/_/BardChatUi/data/AIAssistFrontendService/StreamGenerate")

	for _, secret := range []string{"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI"} {
		if bytes.Contains(got, []byte(url.QueryEscape(secret))) || bytes.Contains(got, []byte(secret)) {
			t.Errorf("credential %q still present after masking;\nbody: %s", secret, got)
		}
	}
	if !bytes.Contains(got, []byte(url.QueryEscape("[REDACTED]"))) && !bytes.Contains(got, []byte("[REDACTED]")) {
		t.Errorf("expected [REDACTED] in output:\n%s", got)
	}
}

func TestMaskMultipartBody_TextFile(t *testing.T) {
	initTestRules(t)

	body := []byte("------WebKitFormBoundaryXXXX\r\n" +
		"Content-Disposition: form-data; name=\"file\"; filename=\"creds.txt\"\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"export AWS_ACCESS_KEY_ID=\"ASIAT42KH7ZNPYF5CREJ\"\n" +
		"export AWS_SECRET_ACCESS_KEY=\"wwb4NMO0srcMX6J67j2jWdadGZ6yKpSZyZKqEYPx\"\n" +
		"\r\n------WebKitFormBoundaryXXXX--\r\n")

	got := MaskSensitiveForService(body, "claude.ai", "/api/organizations/org1/files")

	if bytes.Contains(got, []byte("ASIAT42KH7ZNPYF5CREJ")) {
		t.Errorf("AWS access key not masked: %s", got)
	}
	if bytes.Contains(got, []byte("wwb4NMO0")) {
		t.Errorf("AWS secret key not masked: %s", got)
	}
	if !bytes.Contains(got, []byte("[REDACTED]")) {
		t.Errorf("expected [REDACTED] in output: %s", got)
	}
	// Filename and boundary must be preserved
	if !bytes.Contains(got, []byte("creds.txt")) {
		t.Errorf("filename was removed: %s", got)
	}
}

func TestMaskSensitive_PreservesStructure(t *testing.T) {
	// JSON structure: keys must remain, only the sensitive value gets redacted
	// CRED-001 pattern will match the sk-proj-... value
	input := []byte(`{"api_key":"sk-proj-abc123xxxxxxxxxxxxxxxx","model":"gpt-4"}`)
	got := MaskSensitive(input)

	// The key name must be preserved
	if !bytes.Contains(got, []byte(`"api_key"`)) {
		t.Errorf("JSON key 'api_key' was removed: %q", got)
	}
	if !bytes.Contains(got, []byte(`"model"`)) {
		t.Errorf("JSON key 'model' was removed: %q", got)
	}
	if !bytes.Contains(got, []byte("gpt-4")) {
		t.Errorf("non-sensitive value 'gpt-4' was removed: %q", got)
	}
	// The sensitive value must be gone
	if bytes.Contains(got, []byte("sk-proj-")) {
		t.Errorf("OpenAI key not redacted in JSON: %q", got)
	}
	if !bytes.Contains(got, []byte("[REDACTED]")) {
		t.Errorf("expected [REDACTED] in output: %q", got)
	}
}

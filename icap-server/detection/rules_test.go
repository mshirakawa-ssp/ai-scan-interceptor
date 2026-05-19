package detection

import (
	"strings"
	"testing"
)

var ruleDetector = NewDetector()

// ---- Critical: API key detection ----

func TestRule_OpenAIKey(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"Here is my key: sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"}]}`)
	r, ok := ruleDetector.Detect("api.openai.com", "/v1/chat/completions", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	if r.Severity != "critical" {
		t.Errorf("severity=%q want critical", r.Severity)
	}
	if !hasRule(r, "CRED-001") {
		t.Errorf("expected CRED-001, got %v", ruleIDs(r))
	}
}

func TestRule_AnthropicKey(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"}]}`)
	r, ok := ruleDetector.Detect("api.openai.com", "/v1/chat/completions", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	if !hasRule(r, "CRED-002") {
		t.Errorf("expected CRED-002, got %v", ruleIDs(r))
	}
	if r.Severity != "critical" {
		t.Errorf("severity=%q want critical", r.Severity)
	}
}

func TestRule_AWSAccessKey(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"aws key: AKIAIOSFODNN7EXAMPLE"}]}`)
	r, ok := ruleDetector.Detect("api.openai.com", "/v1/chat/completions", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	if !hasRule(r, "CRED-003") {
		t.Errorf("expected CRED-003, got %v", ruleIDs(r))
	}
}

func TestRule_GitHubToken(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"token=ghp_abcdefghijklmnopqrstuvwxyz0123456789"}]}`)
	r, ok := ruleDetector.Detect("api.openai.com", "/v1/chat/completions", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	if !hasRule(r, "CRED-005") {
		t.Errorf("expected CRED-005, got %v", ruleIDs(r))
	}
}

func TestRule_PrivateKey(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."}]}`)
	r, ok := ruleDetector.Detect("api.openai.com", "/v1/chat/completions", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	if !hasRule(r, "CRED-007") {
		t.Errorf("expected CRED-007, got %v", ruleIDs(r))
	}
}

func TestRule_JWT(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature"}]}`)
	r, ok := ruleDetector.Detect("api.openai.com", "/v1/chat/completions", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	if !hasRule(r, "CRED-008") {
		t.Errorf("expected CRED-008, got %v", ruleIDs(r))
	}
}

// ---- High: credential key-value patterns ----

func TestRule_CredentialAssignment_Triggered(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"db config: password=Sup3rS3cr3t! host=db.internal"}]}`)
	r, ok := ruleDetector.Detect("api.openai.com", "/v1/chat/completions", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	if !hasRule(r, "CRED-101") {
		t.Errorf("expected CRED-101, got %v", ruleIDs(r))
	}
	if r.Severity != "high" {
		t.Errorf("severity=%q want high", r.Severity)
	}
}

func TestRule_CredentialAssignment_FalsePositive_Example(t *testing.T) {
	// "example" in negative context → should NOT trigger CRED-101
	body := []byte(`{"messages":[{"role":"user","content":"for example: password=your_password_here"}]}`)
	r, ok := ruleDetector.Detect("api.openai.com", "/v1/chat/completions", "POST", body)
	if !ok {
		t.Fatal("expected match (still captured as AI request)")
	}
	if hasRule(r, "CRED-101") {
		t.Error("CRED-101 should be suppressed for placeholder pattern")
	}
}

func TestRule_CredentialAssignment_FalsePositive_HowTo(t *testing.T) {
	// "how to" in negative context → should NOT trigger CRED-101
	body := []byte(`{"messages":[{"role":"user","content":"How to set api_key=... in Python config?"}]}`)
	r, ok := ruleDetector.Detect("api.openai.com", "/v1/chat/completions", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	if hasRule(r, "CRED-101") {
		t.Error("CRED-101 should be suppressed for how-to context")
	}
}

// ---- High: Japanese PII ----

func TestRule_JapaneseConfidential(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"この機密情報を英語に翻訳してください"}]}]}`)
	r, ok := ruleDetector.Detect("claude.ai", "/api/organizations/org1/messages", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	if !hasRule(r, "PII-101") {
		t.Errorf("expected PII-101, got %v", ruleIDs(r))
	}
	if r.Severity != "high" {
		t.Errorf("severity=%q want high", r.Severity)
	}
}

// ---- Medium: password in context (with FP suppression) ----

func TestRule_PasswordContext_Triggered(t *testing.T) {
	// Disclosure context: no suppression keywords
	body := []byte(`{"messages":[{"role":"user","content":"My DB password is abc123, is that secure?"}]}`)
	r, ok := ruleDetector.Detect("api.openai.com", "/v1/chat/completions", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	if !hasRule(r, "KEYWORD-201") {
		t.Errorf("expected KEYWORD-201, got %v", ruleIDs(r))
	}
}

func TestRule_PasswordContext_Suppressed_Validation(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"How do I validate password length in Go?"}]}`)
	r, ok := ruleDetector.Detect("api.openai.com", "/v1/chat/completions", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	if hasRule(r, "KEYWORD-201") {
		t.Error("KEYWORD-201 should be suppressed for validation/how-to context")
	}
}

func TestRule_PasswordContext_Suppressed_Reset(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"How to reset your password if you forgot it?"}]}`)
	r, ok := ruleDetector.Detect("api.openai.com", "/v1/chat/completions", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	if hasRule(r, "KEYWORD-201") {
		t.Error("KEYWORD-201 should be suppressed for forgot/reset context")
	}
}

// ---- Severity prioritization ----

func TestRule_SeverityPriority(t *testing.T) {
	// Body has both a high rule (credential assignment) and a medium rule (password keyword)
	body := []byte(`{"messages":[{"role":"user","content":"My password is set to api_key=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"}]}`)
	r, ok := ruleDetector.Detect("api.openai.com", "/v1/chat/completions", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	// CRED-001 (critical) should dominate
	if r.Severity != "critical" {
		t.Errorf("severity=%q want critical (highest wins)", r.Severity)
	}
}

// ---- Critical: AWS Secret Key / Session Token (JSON-quoted format) ----

func TestRule_AWSSecretKey_Plain(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"aws_secret_access_key=wwb4NMO0srcMX6J67j2jWdadGZ6yKpSZyZKqEYPx"}]}`)
	r, ok := ruleDetector.Detect("api.openai.com", "/v1/chat/completions", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	if !hasRule(r, "CRED-004") {
		t.Errorf("expected CRED-004, got %v", ruleIDs(r))
	}
}

func TestRule_AWSSecretKey_JSONQuoted(t *testing.T) {
	// export AWS_SECRET_ACCESS_KEY="value" becomes KEY=\"value\" in JSON body
	body := []byte(`{"messages":[{"role":"user","content":"export AWS_SECRET_ACCESS_KEY=\"wwb4NMO0srcMX6J67j2jWdadGZ6yKpSZyZKqEYPx\""}]}`)
	r, ok := ruleDetector.Detect("api.openai.com", "/v1/chat/completions", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	if !hasRule(r, "CRED-004") {
		t.Errorf("expected CRED-004 for JSON-escaped quoted value, got %v", ruleIDs(r))
	}
}

func TestRule_AWSSessionToken_Plain(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"aws_session_token=IQoJb3JpZ2luX2VjELL//////////wEaCXVzLWVhc3QtMSJIMEYCIQD0123456789abcdefghij=="}]}`)
	r, ok := ruleDetector.Detect("api.openai.com", "/v1/chat/completions", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	if !hasRule(r, "CRED-009") {
		t.Errorf("expected CRED-009, got %v", ruleIDs(r))
	}
}

func TestRule_AWSSessionToken_JSONQuoted(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"export AWS_SESSION_TOKEN=\"IQoJb3JpZ2luX2VjELL//////////wEaCXVzLWVhc3QtMSJIMEYCIQD0123456789abcdefghij==\""}]}`)
	r, ok := ruleDetector.Detect("api.openai.com", "/v1/chat/completions", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	if !hasRule(r, "CRED-009") {
		t.Errorf("expected CRED-009 for JSON-escaped quoted value, got %v", ruleIDs(r))
	}
}

// ---- api.anthropic.com ----

func TestDetect_AnthropicAPI(t *testing.T) {
	body := []byte(`{"model":"claude-3-opus-20240229","messages":[{"role":"user","content":"What is the speed of light?"}]}`)
	r, ok := ruleDetector.Detect("api.anthropic.com", "/v1/messages", "POST", body)
	if !ok {
		t.Fatal("expected match for api.anthropic.com /v1/messages")
	}
	if r.Service != "Claude-API" {
		t.Errorf("service=%q want Claude-API", r.Service)
	}
	if !strings.Contains(r.Prompt, "speed of light") {
		t.Errorf("prompt=%q", r.Prompt)
	}
}

func TestDetect_AnthropicAPI_WithSystem(t *testing.T) {
	body := []byte(`{"model":"claude-3-sonnet","system":"You are a helpful assistant.","messages":[{"role":"user","content":"Explain Go generics."}]}`)
	r, ok := ruleDetector.Detect("api.anthropic.com", "/v1/messages", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	if !strings.Contains(r.Prompt, "[system] You are a helpful assistant.") {
		t.Errorf("system prompt not extracted: %q", r.Prompt)
	}
	if !strings.Contains(r.Prompt, "Explain Go generics") {
		t.Errorf("user prompt not extracted: %q", r.Prompt)
	}
}

// ---- Gemini v1 path ----

func TestDetect_Gemini_V1Path(t *testing.T) {
	body := []byte(`{"contents":[{"parts":[{"text":"Translate to Japanese: hello"}],"role":"user"}]}`)
	r, ok := ruleDetector.Detect("generativelanguage.googleapis.com", "/v1/models/gemini-pro/generateContent", "POST", body)
	if !ok {
		t.Fatal("expected match for Gemini /v1/ path")
	}
	if r.Service != "Gemini" {
		t.Errorf("service=%q", r.Service)
	}
}

// ---- helpers ----

func hasRule(r *Result, id string) bool {
	for _, rm := range r.RuleMatches {
		if rm.RuleID == id {
			return true
		}
	}
	return false
}

func ruleIDs(r *Result) []string {
	ids := make([]string, len(r.RuleMatches))
	for i, rm := range r.RuleMatches {
		ids[i] = rm.RuleID
	}
	return ids
}

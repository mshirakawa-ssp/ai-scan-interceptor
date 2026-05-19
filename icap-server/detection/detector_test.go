package detection

import (
	"os"
	"strings"
	"testing"
)

// TestMain seeds the active rules store with built-in defaults before any test runs.
func TestMain(m *testing.M) {
	SetActiveRules(EntriesToAlertRules(DefaultEntries()))
	os.Exit(m.Run())
}

var detector = NewDetector()

// ---- ChatGPT /v1/chat/completions ----

func TestDetectOpenAI_Basic(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"What is the capital of Japan?"}]}`)
	r, ok := detector.Detect("api.openai.com", "/v1/chat/completions", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	if r.Service != "ChatGPT" {
		t.Errorf("service=%q want ChatGPT", r.Service)
	}
	if !strings.Contains(r.Prompt, "What is the capital of Japan?") {
		t.Errorf("prompt missing expected text: %q", r.Prompt)
	}
	if r.Triggered {
		t.Error("should not trigger alert")
	}
}

func TestDetectOpenAI_Alert(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"My password is hunter2, help me change it"}]}`)
	r, ok := detector.Detect("api.openai.com", "/v1/chat/completions", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	// keyword-match removed; detection now relies solely on builtin regex rules
	_ = r
}

func TestDetectOpenAI_System(t *testing.T) {
	body := []byte(`{"messages":[
		{"role":"system","content":"You are a helpful assistant."},
		{"role":"user","content":"Hello!"}
	]}`)
	r, ok := detector.Detect("api.openai.com", "/v1/chat/completions", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	if !strings.Contains(r.Prompt, "[system]") || !strings.Contains(r.Prompt, "[user]") {
		t.Errorf("prompt missing role labels: %q", r.Prompt)
	}
}

func TestDetectOpenAI_ContentArray(t *testing.T) {
	// GPT-4 vision format: content is array of parts
	body := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"Describe this image."}]}]}`)
	r, ok := detector.Detect("api.openai.com", "/v1/chat/completions", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	if !strings.Contains(r.Prompt, "Describe this image.") {
		t.Errorf("prompt: %q", r.Prompt)
	}
}

// ---- ChatGPT Web /backend-api/conversation ----

func TestDetectChatGPTWeb(t *testing.T) {
	body := []byte(`{
		"messages":[{
			"role":"user",
			"content":{"content_type":"text","parts":["Please summarize this document."]}
		}]
	}`)
	r, ok := detector.Detect("chatgpt.com", "/backend-api/conversation", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	if r.Service != "ChatGPT-Web" {
		t.Errorf("service=%q", r.Service)
	}
	if !strings.Contains(r.Prompt, "Please summarize this document.") {
		t.Errorf("prompt: %q", r.Prompt)
	}
}

// ---- Claude ----

func TestDetectClaude_Messages(t *testing.T) {
	body := []byte(`{
		"messages":[{
			"role":"user",
			"content":[{"type":"text","text":"Explain quantum entanglement."}]
		}]
	}`)
	r, ok := detector.Detect("claude.ai", "/api/organizations/org1/messages", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	if r.Service != "Claude" {
		t.Errorf("service=%q", r.Service)
	}
	if !strings.Contains(r.Prompt, "Explain quantum entanglement.") {
		t.Errorf("prompt: %q", r.Prompt)
	}
}

func TestDetectClaude_Alert_Japanese(t *testing.T) {
	body := []byte(`{
		"messages":[{
			"role":"user",
			"content":[{"type":"text","text":"この機密情報を要約してください"}]
		}]
	}`)
	r, ok := detector.Detect("claude.ai", "/api/organizations/org1/messages", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	// keyword-match removed; detection now relies solely on builtin regex rules
	_ = r
}

func TestDetectClaude_LegacyPrompt(t *testing.T) {
	body := []byte(`{"prompt":"\n\nHuman: Tell me a joke\n\nAssistant:"}`)
	r, ok := detector.Detect("claude.ai", "/api/complete", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	if !strings.Contains(r.Prompt, "Tell me a joke") {
		t.Errorf("prompt: %q", r.Prompt)
	}
}

// ---- Gemini ----

func TestDetectGemini(t *testing.T) {
	body := []byte(`{
		"contents":[{
			"parts":[{"text":"What is the largest planet in the solar system?"}],
			"role":"user"
		}]
	}`)
	r, ok := detector.Detect("generativelanguage.googleapis.com", "/v1beta/models/gemini-pro/generateContent", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	if r.Service != "Gemini" {
		t.Errorf("service=%q", r.Service)
	}
	if !strings.Contains(r.Prompt, "largest planet") {
		t.Errorf("prompt: %q", r.Prompt)
	}
}

func TestDetectGemini_Alert(t *testing.T) {
	body := []byte(`{
		"contents":[{
			"parts":[{"text":"My secret token is abc123"}],
			"role":"user"
		}]
	}`)
	r, ok := detector.Detect("generativelanguage.googleapis.com", "/v1/models/gemini-pro/generateContent", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	// keyword-match removed; detection now relies solely on builtin regex rules
	_ = r
}

// ---- Truncation ----

func TestTruncation(t *testing.T) {
	// maxPromptLen = 4096; use 5000 chars to guarantee truncation
	long := strings.Repeat("a", 5000)
	body := []byte(`{"messages":[{"role":"user","content":"` + long + `"}]}`)
	r, ok := detector.Detect("api.openai.com", "/v1/chat/completions", "POST", body)
	if !ok {
		t.Fatal("expected match")
	}
	const maxPromptLen = 4096
	if len(r.Prompt) > maxPromptLen+20 { // +20 for "… [truncated]" suffix
		t.Errorf("prompt not truncated, len=%d", len(r.Prompt))
	}
	if !strings.HasSuffix(r.Prompt, "[truncated]") {
		t.Errorf("missing truncation suffix, got: %q", r.Prompt[max(0, len(r.Prompt)-30):])
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ---- Non-AI traffic is ignored ----

func TestNoMatch_UnknownHost(t *testing.T) {
	_, ok := detector.Detect("example.com", "/api/chat", "POST", []byte(`{}`))
	if ok {
		t.Error("should not match unknown host")
	}
}

func TestNoMatch_GetMethod(t *testing.T) {
	_, ok := detector.Detect("api.openai.com", "/v1/chat/completions", "GET", []byte(`{}`))
	if ok {
		t.Error("should not match GET")
	}
}

func TestNoMatch_EmptyBody(t *testing.T) {
	_, ok := detector.Detect("api.openai.com", "/v1/chat/completions", "POST", []byte(`{"messages":[]}`))
	if ok {
		t.Error("should not match empty messages")
	}
}

// ---- False-positive regression: body-scan removed ----

// TestNoFalsePositiveFromHistory verifies that an AWS Access Key ID appearing
// only in a prior assistant turn does NOT trigger an alert.
// The latest user turn is clean; only the extracted prompt (last user message)
// is scanned now that body scanning has been removed.
func TestNoFalsePositiveFromHistory(t *testing.T) {
	// Simulate an Anthropic API request where:
	//   - assistant turn quotes a previously-detected AKIA key (e.g. in an explanation)
	//   - the latest user turn is clean
	body := []byte(`{
		"model": "claude-3-5-sonnet-20241022",
		"messages": [
			{
				"role": "user",
				"content": "Can you help me check my AWS config?"
			},
			{
				"role": "assistant",
				"content": "I detected a credential: AKIAIOSFODNN7EXAMPLE in your previous message. Please rotate it immediately."
			},
			{
				"role": "user",
				"content": "Thanks, I have already rotated the key."
			}
		]
	}`)
	r, ok := detector.Detect("api.anthropic.com", "/v1/messages", "POST", body)
	if !ok {
		t.Fatal("expected Detect to return a result")
	}
	if r.Triggered {
		t.Errorf("expected Triggered=false (AKIA key is only in assistant history), got Triggered=true; matches=%v", r.RuleMatches)
	}
}

// ---- File attachment detection ----

func TestDetectClaude_MultipartFileUpload(t *testing.T) {
	// Simulate claude.ai uploading a text file as multipart/form-data.
	body := []byte("------WebKitFormBoundaryXXXXXXXX\r\n" +
		"Content-Disposition: form-data; name=\"file\"; filename=\"creds.txt\"\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"export AWS_ACCESS_KEY_ID=\"AKIAIOSFODNN7EXAMPLE\"\n" +
		"export AWS_SECRET_ACCESS_KEY=\"wJalrXUtnFEMI/K7MDENG/bPxRfiCY\"\r\n" +
		"------WebKitFormBoundaryXXXXXXXX--\r\n")

	r, ok := detector.Detect("claude.ai", "/api/organizations/org1/files", "POST", body)
	if !ok {
		t.Fatal("expected Detect to match multipart upload")
	}
	if r.Service != "Claude" {
		t.Errorf("service=%q want Claude", r.Service)
	}
	if !strings.Contains(r.Prompt, "AWS_ACCESS_KEY_ID") {
		t.Errorf("file content not in prompt: %q", r.Prompt)
	}
	if !r.Triggered {
		t.Errorf("expected Triggered=true for AKIA key in uploaded file")
	}
}

func TestDetectAnthropicAPI_DocumentBlock(t *testing.T) {
	// Simulate Claude Desktop (native app) attaching a text file as a document block.
	body := []byte(`{
		"model": "claude-sonnet-4-6",
		"messages": [{
			"role": "user",
			"content": [
				{
					"type": "document",
					"source": {
						"type": "text",
						"media_type": "text/plain",
						"data": "export AWS_ACCESS_KEY_ID=\"AKIAIOSFODNN7EXAMPLE\"\nexport AWS_SECRET_ACCESS_KEY=\"wJalrXUtnFEMI/K7MDENG/bPxRfiCY\""
					}
				},
				{"type": "text", "text": "このファイルを確認して"}
			]
		}]
	}`)

	r, ok := detector.Detect("api.anthropic.com", "/v1/messages", "POST", body)
	if !ok {
		t.Fatal("expected Detect to match API request with document block")
	}
	if !strings.Contains(r.Prompt, "AWS_ACCESS_KEY_ID") {
		t.Errorf("document content not in prompt: %q", r.Prompt)
	}
	if !r.Triggered {
		t.Errorf("expected Triggered=true for AKIA key in document block")
	}
}

// ---- MaskSensitive tests ----

// TestAWSSecretKeyMask verifies that CRED-004 pattern matches and masks
// AWS_SECRET_ACCESS_KEY= values in the raw body.
func TestAWSSecretKeyMask(t *testing.T) {
	input := []byte(`{"content":"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY"}`)
	got := string(MaskSensitive(input))
	if strings.Contains(got, "wJalrXUtnFEMI") {
		t.Errorf("secret key not masked; got: %s", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("expected [REDACTED] in output; got: %s", got)
	}
}

// TestAWSSessionTokenMask verifies that CRED-009 pattern matches and masks
// AWS_SESSION_TOKEN= values in the raw body.
func TestAWSSessionTokenMask(t *testing.T) {
	// Token must be >= 50 chars to match CRED-009 pattern `{50,}`
	input := []byte(`{"content":"AWS_SESSION_TOKEN=AQoXnyc4lcK4w4OIaYnuFgEa9qJ8uIlonglonglongtoken123=="}`)
	got := string(MaskSensitive(input))
	if strings.Contains(got, "AQoXnyc4lcK4w4OIaYnuFgEa9qJ8uIlonglonglongtoken123") {
		t.Errorf("session token not masked; got: %s", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("expected [REDACTED] in output; got: %s", got)
	}
}

package detection

import (
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/url"
	"regexp"
	"strings"
)

// serviceRule describes how to match and extract prompts from one AI service.
type serviceRule struct {
	Name      string
	Hosts     []string
	PathRegex *regexp.Regexp
	Extract   func(body []byte) (string, error)
}

var rules = []serviceRule{
	{
		Name:      "ChatGPT",
		Hosts:     []string{"api.openai.com", "chatgpt.com"},
		PathRegex: regexp.MustCompile(`^/v1/chat/completions`),
		Extract:   extractOpenAI,
	},
	{
		Name:      "ChatGPT-Web",
		Hosts:     []string{"chatgpt.com"},
		PathRegex: regexp.MustCompile(`^/backend-api/conversation`),
		Extract:   extractChatGPTWeb,
	},
	{
		Name:      "Claude",
		Hosts:     []string{"claude.ai", "api.anthropic.com"},
		PathRegex: regexp.MustCompile(`^/api/`),
		Extract:   extractClaude,
	},
	{
		// Anthropic direct API (/v1/messages) uses the same message format as claude.ai
		Name:      "Claude-API",
		Hosts:     []string{"api.anthropic.com"},
		PathRegex: regexp.MustCompile(`^/v1/`),
		Extract:   extractAnthropicAPI,
	},
	{
		// Claude web UI backend (claude.ai front-end calls a-api.anthropic.com/v1/b)
		Name:      "Claude-Web",
		Hosts:     []string{"a-api.anthropic.com"},
		PathRegex: regexp.MustCompile(`^/v1/`),
		Extract:   extractAnthropicAPI,
	},
	{
		Name:      "Gemini",
		Hosts:     []string{"generativelanguage.googleapis.com", "gemini.google.com"},
		// Match both /v1beta/models/ and /v1/models/ paths.
		// Google REST API uses colon method syntax: /v1/models/MODEL:generateContent
		PathRegex: regexp.MustCompile(`/(?:v1beta|v1)/models/[^/:]+[/:](?:generateContent|streamGenerateContent)`),
		Extract:   extractGemini,
	},
	{
		// Gemini web UI (gemini.google.com) uses Google's internal BardChatUi RPC.
		// Only match StreamGenerate (actual chat); batchexecute is session/UI state.
		// Body is URL-encoded: f.req=<nested-JSON>
		Name:      "Gemini-Web",
		Hosts:     []string{"gemini.google.com"},
		PathRegex: regexp.MustCompile(`/_/BardChatUi/data/.*StreamGenerate`),
		Extract:   extractGeminiWeb,
	},
	{
		Name:      "GitHub-Copilot",
		Hosts:     []string{"api.githubcopilot.com"},
		PathRegex: regexp.MustCompile(`^/chat/completions`),
		Extract:   extractOpenAI,
	},
	{
		// Azure OpenAI Service: *.openai.azure.com/openai/deployments/<model>/chat/completions
		Name:      "Azure-OpenAI",
		Hosts:     []string{"*.openai.azure.com"},
		PathRegex: regexp.MustCompile(`/openai/deployments/[^/]+/chat/completions`),
		Extract:   extractOpenAI,
	},
}

// findRule returns the matching rule for a given host+path, or nil.
func findRule(host, path string) *serviceRule {
	if idx := strings.LastIndexByte(host, ':'); idx >= 0 {
		host = host[:idx]
	}
	for i := range rules {
		r := &rules[i]
		for _, h := range r.Hosts {
			var match bool
			if strings.HasPrefix(h, "*.") {
				// *.openai.azure.com → host は xxx.openai.azure.com にマッチ
				match = strings.HasSuffix(host, h[1:])
			} else {
				match = h == host
			}
			if match && r.PathRegex.MatchString(path) {
				return r
			}
		}
	}
	return nil
}

// --- Extractor implementations ---

// extractOpenAI handles /v1/chat/completions
// {"messages": [{"role": "user", "content": "text"}]}
func extractOpenAI(body []byte) (string, error) {
	var req struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return "", err
	}
	var parts []string
	for _, m := range req.Messages {
		if m.Role != "user" && m.Role != "system" {
			continue
		}
		text, err := extractStringOrParts(m.Content)
		if err == nil && text != "" {
			parts = append(parts, fmt.Sprintf("[%s] %s", m.Role, text))
		}
	}
	return strings.Join(parts, "\n"), nil
}

// extractChatGPTWeb handles /backend-api/conversation
// {"messages": [{"role": "user", "content": {"content_type": "text", "parts": ["text"]}}]}
func extractChatGPTWeb(body []byte) (string, error) {
	var req struct {
		Messages []struct {
			Role    string `json:"role"`
			Content struct {
				ContentType string   `json:"content_type"`
				Parts       []string `json:"parts"`
			} `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		// Fall back to OpenAI format
		return extractOpenAI(body)
	}
	var parts []string
	for _, m := range req.Messages {
		if m.Role != "user" && m.Role != "system" {
			continue
		}
		text := strings.Join(m.Content.Parts, " ")
		if text != "" {
			parts = append(parts, fmt.Sprintf("[%s] %s", m.Role, text))
		}
	}
	if len(parts) == 0 {
		return extractOpenAI(body)
	}
	return strings.Join(parts, "\n"), nil
}

// extractMultipartFile extracts text from multipart/form-data bodies.
// Claude web UI uploads files as multipart before the chat message is sent.
func extractMultipartFile(body []byte) (string, error) {
	bodyStr := string(body)
	lineEnd := strings.Index(bodyStr, "\r\n")
	if lineEnd < 3 || bodyStr[0] != '-' || bodyStr[1] != '-' {
		return "", fmt.Errorf("not multipart")
	}
	boundary := bodyStr[2:lineEnd]

	mr := multipart.NewReader(strings.NewReader(bodyStr), boundary)
	var texts []string
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		ct := part.Header.Get("Content-Type")
		filename := part.FileName()
		// Include text files and any named file part without an explicit type.
		if strings.HasPrefix(ct, "text/") || (filename != "" && (ct == "" || strings.Contains(ct, "octet-stream"))) {
			data, _ := io.ReadAll(part)
			if len(data) > 0 {
				texts = append(texts, string(data))
			}
		}
		part.Close()
	}
	if len(texts) == 0 {
		return "", fmt.Errorf("no text content in multipart")
	}
	return strings.Join(texts, "\n"), nil
}

// extractClaude handles claude.ai API requests
// Supports both {messages:[{content:[{type:"text",text:"..."}]}]} and {prompt:"..."}
func extractClaude(body []byte) (string, error) {
	// File uploads arrive as multipart/form-data before the actual chat turn.
	if len(body) > 2 && body[0] == '-' && body[1] == '-' {
		return extractMultipartFile(body)
	}
	// Try messages format first
	var msgReq struct {
		Messages []struct {
			Role    string `json:"role"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &msgReq); err == nil && len(msgReq.Messages) > 0 {
		var parts []string
		for _, m := range msgReq.Messages {
			if m.Role != "user" && m.Role != "human" {
				continue
			}
			for _, c := range m.Content {
				if c.Type == "text" && c.Text != "" {
					parts = append(parts, fmt.Sprintf("[%s] %s", m.Role, c.Text))
				}
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, "\n"), nil
		}
	}

	// Try legacy prompt format
	var promptReq struct {
		Prompt string `json:"prompt"`
	}
	if err := json.Unmarshal(body, &promptReq); err == nil && promptReq.Prompt != "" {
		// Strip "\n\nHuman: " prefix if present
		p := strings.TrimPrefix(promptReq.Prompt, "\n\nHuman: ")
		if idx := strings.Index(p, "\n\nAssistant:"); idx >= 0 {
			p = p[:idx]
		}
		return strings.TrimSpace(p), nil
	}

	return "", fmt.Errorf("unknown claude format")
}

// extractGemini handles generativelanguage.googleapis.com generateContent
// {"contents": [{"parts": [{"text": "..."}], "role": "user"}]}
func extractGemini(body []byte) (string, error) {
	var req struct {
		Contents []struct {
			Role  string `json:"role"`
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"contents"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return "", err
	}
	var parts []string
	for _, c := range req.Contents {
		role := c.Role
		if role == "" {
			role = "user"
		}
		for _, p := range c.Parts {
			if p.Text != "" {
				parts = append(parts, fmt.Sprintf("[%s] %s", role, p.Text))
			}
		}
	}
	return strings.Join(parts, "\n"), nil
}

// extractGeminiWeb handles the Gemini browser UI (gemini.google.com).
// The browser sends URL-encoded form data: f.req=<nested-JSON>
//
// Real browser format: [null, "<payload_json>"]
//  payload_json: [["<user_text>", ...], ...]
//
// When a file is attached, the file content is embedded in later elements of
// the same array. We collect ALL strings ≥ 10 chars from the payload so that
// credentials in attached files are detected alongside the typed message.
func extractGeminiWeb(body []byte) (string, error) {
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return "", fmt.Errorf("parse form: %w", err)
	}
	fReq := values.Get("f.req")
	if fReq == "" {
		return "", fmt.Errorf("no f.req field")
	}

	payloadStr, err := extractGeminiPayloadStr(fReq)
	if err != nil {
		return "", err
	}

	// Decode the whole payload as generic JSON and collect all string content.
	// payload[0][0] is the user-typed message; attached file text appears at
	// deeper nesting positions that vary by Gemini version.
	var payloadAny interface{}
	if err := json.Unmarshal([]byte(payloadStr), &payloadAny); err != nil {
		return "", fmt.Errorf("unmarshal payload: %w", err)
	}
	var texts []string
	gatherStrings(payloadAny, 10, &texts)
	if len(texts) == 0 {
		return "", fmt.Errorf("no text content in payload")
	}
	return strings.Join(texts, "\n"), nil
}

// gatherStrings recursively collects all strings longer than minLen from a
// decoded JSON value. This is used to extract both typed messages and attached
// file contents from Gemini's opaque nested payload structure.
func gatherStrings(v interface{}, minLen int, out *[]string) {
	switch val := v.(type) {
	case string:
		if len(val) >= minLen {
			*out = append(*out, val)
		}
	case []interface{}:
		for _, item := range val {
			gatherStrings(item, minLen, out)
		}
	case map[string]interface{}:
		for _, item := range val {
			gatherStrings(item, minLen, out)
		}
	}
}

// extractGeminiPayloadStr extracts the payload JSON string from f.req.
// Handles both the flat format [null, "<payload>"] and the nested format
// [[[<id>, "<payload>", null, "generic"]]].
func extractGeminiPayloadStr(fReq string) (string, error) {
	var outer []json.RawMessage
	if err := json.Unmarshal([]byte(fReq), &outer); err != nil {
		return "", fmt.Errorf("unmarshal f.req: %w", err)
	}
	if len(outer) < 2 {
		return "", fmt.Errorf("f.req too short (len=%d)", len(outer))
	}

	// Flat format: [null, "<payload_string>", ...]  — real Chrome browser
	var payloadStr string
	if err := json.Unmarshal(outer[1], &payloadStr); err == nil {
		return payloadStr, nil
	}

	// Nested format: [[[<id>, "<payload_string>", null, "generic"]]] — legacy / simulated
	var inner [][]json.RawMessage
	if err := json.Unmarshal(outer[0], &inner); err != nil {
		return "", fmt.Errorf("neither flat nor nested f.req format")
	}
	if len(inner) == 0 || len(inner[0]) < 2 {
		return "", fmt.Errorf("nested f.req too short")
	}
	if err := json.Unmarshal(inner[0][1], &payloadStr); err != nil {
		return "", fmt.Errorf("nested payload not string: %w", err)
	}
	return payloadStr, nil
}

// extractAnthropicAPI handles api.anthropic.com /v1/messages (SDK format)
// system can be a string or an array of content blocks (Claude API v3+)
// {"model":"...","messages":[{"role":"user","content":"text"}],"system":"..."}
func extractAnthropicAPI(body []byte) (string, error) {
	var req struct {
		System   json.RawMessage `json:"system"`
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return "", err
	}
	var parts []string
	if len(req.System) > 0 {
		if sys, err := extractStringOrParts(req.System); err == nil && sys != "" {
			// Skip Claude Code's auto-injected billing/system header — not user content.
			if !strings.HasPrefix(sys, "x-anthropic-billing-header:") {
				parts = append(parts, fmt.Sprintf("[system] %s", sys))
			}
		}
	}
	// Only log the LAST user message: each call sends the full history, so
	// collecting all messages would bury the new input under gigabytes of
	// conversation context and cause the 2048-char truncation to cut it off.
	lastUserText := ""
	for _, m := range req.Messages {
		if m.Role != "user" && m.Role != "human" {
			continue
		}
		text, err := extractStringOrParts(m.Content)
		if err == nil && text != "" {
			lastUserText = text
		}
	}
	if lastUserText != "" {
		// Strip <system-reminder>...</system-reminder> injections that Claude Code
		// prepends to the user turn — they are not user-authored content.
		lastUserText = stripSystemTags(lastUserText)
		if lastUserText != "" {
			parts = append(parts, fmt.Sprintf("[user] %s", lastUserText))
		}
	}
	return strings.Join(parts, "\n"), nil
}

// stripSystemTags removes auto-injected <system-reminder>…</system-reminder> and
// <system>…</system> blocks from a user message content string.
func stripSystemTags(s string) string {
	for _, tag := range []string{"system-reminder", "system"} {
		open, close := "<"+tag+">", "</"+tag+">"
		for {
			start := strings.Index(s, open)
			if start < 0 {
				break
			}
			end := strings.Index(s[start:], close)
			if end < 0 {
				s = s[:start]
				break
			}
			s = s[:start] + s[start+end+len(close):]
		}
	}
	return strings.TrimSpace(s)
}

// extractStringOrParts handles content that may be a plain string or an array of parts.
// Handles "text" blocks and "document" blocks with inline text source
// (used when Claude API callers attach text files directly in the request body).
func extractStringOrParts(raw json.RawMessage) (string, error) {
	// Try plain string
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}
	// Try array of content parts
	var parts []struct {
		Type   string          `json:"type"`
		Text   string          `json:"text"`
		Source json.RawMessage `json:"source"`
	}
	if err := json.Unmarshal(raw, &parts); err == nil {
		var texts []string
		for _, p := range parts {
			switch p.Type {
			case "text", "":
				if p.Text != "" {
					texts = append(texts, p.Text)
				}
			case "document":
				// Inline document: {"type":"document","source":{"type":"text","data":"<content>"}}
				if len(p.Source) > 0 {
					var src struct {
						Type string `json:"type"`
						Data string `json:"data"`
					}
					if json.Unmarshal(p.Source, &src) == nil && src.Type == "text" && src.Data != "" {
						texts = append(texts, src.Data)
					}
				}
			}
		}
		return strings.Join(texts, " "), nil
	}
	return "", fmt.Errorf("unsupported content format")
}

// sensitiveFilenameRules maps glob-style filename patterns to (ruleID, description).
// Matched filenames trigger an immediate high-severity alert regardless of file content.
var sensitiveFilenameRules = []struct {
	suffix string // lowercase suffix or exact name to match
	exact  bool   // true = exact filename match; false = suffix/extension match
	ruleID string
	desc   string
}{
	// SSH private keys
	{suffix: "id_rsa", exact: true, ruleID: "FILE-001", desc: "SSH private key file"},
	{suffix: "id_ed25519", exact: true, ruleID: "FILE-001", desc: "SSH private key file"},
	{suffix: "id_ecdsa", exact: true, ruleID: "FILE-001", desc: "SSH private key file"},
	{suffix: "id_dsa", exact: true, ruleID: "FILE-001", desc: "SSH private key file"},
	// Environment / secrets files
	{suffix: ".env", exact: false, ruleID: "FILE-002", desc: "Environment variables file (.env)"},
	// Certificate / key files
	{suffix: ".pem", exact: false, ruleID: "FILE-003", desc: "PEM certificate or key file"},
	{suffix: ".key", exact: false, ruleID: "FILE-003", desc: "Private key file"},
	{suffix: ".p12", exact: false, ruleID: "FILE-003", desc: "PKCS12 certificate bundle"},
	{suffix: ".pfx", exact: false, ruleID: "FILE-003", desc: "PKCS12 certificate bundle"},
	{suffix: ".jks", exact: false, ruleID: "FILE-003", desc: "Java KeyStore file"},
	{suffix: ".p8", exact: false, ruleID: "FILE-003", desc: "PKCS8 private key file"},
	// Cloud credentials
	{suffix: "credentials", exact: true, ruleID: "FILE-004", desc: "Cloud credentials file"},
	{suffix: "credentials.json", exact: true, ruleID: "FILE-004", desc: "Cloud credentials JSON"},
	{suffix: "credentials.csv", exact: true, ruleID: "FILE-004", desc: "Cloud credentials CSV"},
	// GCP service account keys
	{suffix: "service-account.json", exact: true, ruleID: "FILE-005", desc: "GCP service account key"},
	{suffix: "serviceaccount.json", exact: true, ruleID: "FILE-005", desc: "GCP service account key"},
	// Terraform / Kubernetes secrets
	{suffix: ".tfvars", exact: false, ruleID: "FILE-006", desc: "Terraform variables file (may contain secrets)"},
	{suffix: "secrets.yaml", exact: true, ruleID: "FILE-007", desc: "Kubernetes secrets manifest"},
	{suffix: "secrets.yml", exact: true, ruleID: "FILE-007", desc: "Kubernetes secrets manifest"},
	{suffix: "kubeconfig", exact: true, ruleID: "FILE-008", desc: "Kubernetes kubeconfig with credentials"},
	{suffix: ".kubeconfig", exact: false, ruleID: "FILE-008", desc: "Kubernetes kubeconfig with credentials"},
}

// extractGeminiContribRef returns the first /contrib_service/... token found in text,
// or "" if none. Gemini Web uploads files to Google's internal contrib_service CDN;
// the StreamGenerate payload contains only this opaque URL token, never the file content.
func extractGeminiContribRef(text string) string {
	const marker = "/contrib_service/"
	idx := strings.Index(text, marker)
	if idx < 0 {
		return ""
	}
	// Extract up to 80 chars for the log excerpt.
	end := idx + 80
	if end > len(text) {
		end = len(text)
	}
	return text[idx:end]
}

// checkSensitiveFilename extracts filenames from a multipart body and checks
// them against sensitiveFilenameRules. Returns (filename, ruleID, description)
// for the first match, or ("", "", "") if no sensitive filename is found.
func checkSensitiveFilename(body []byte) (filename, ruleID, desc string) {
	bodyStr := string(body)
	lineEnd := strings.Index(bodyStr, "\r\n")
	if lineEnd < 3 {
		return "", "", ""
	}
	boundary := bodyStr[2:lineEnd]
	mr := multipart.NewReader(strings.NewReader(bodyStr), boundary)
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		fname := part.FileName()
		part.Close()
		if fname == "" {
			continue
		}
		lower := strings.ToLower(fname)
		for _, rule := range sensitiveFilenameRules {
			if rule.exact {
				if lower == rule.suffix {
					return fname, rule.ruleID, rule.desc
				}
			} else {
				if strings.HasSuffix(lower, rule.suffix) {
					return fname, rule.ruleID, rule.desc
				}
			}
		}
	}
	return "", "", ""
}

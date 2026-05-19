package detection

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestFindRule_GitHubCopilot(t *testing.T) {
	rule := findRule("api.githubcopilot.com", "/chat/completions")
	if rule == nil {
		t.Fatal("expected rule to match GitHub-Copilot, got nil")
	}
	if rule.Name != "GitHub-Copilot" {
		t.Errorf("rule.Name=%q want %q", rule.Name, "GitHub-Copilot")
	}
}

func TestFindRule_AzureOpenAI(t *testing.T) {
	tests := []struct {
		name string
		host string
		path string
	}{
		{
			name: "standard deployment",
			host: "mydeployment.openai.azure.com",
			path: "/openai/deployments/gpt4/chat/completions",
		},
		{
			name: "other subdomain",
			host: "mycompany-eastus.openai.azure.com",
			path: "/openai/deployments/gpt-35-turbo/chat/completions",
		},
		{
			name: "single label subdomain",
			host: "x.openai.azure.com",
			path: "/openai/deployments/gpt4o/chat/completions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := findRule(tt.host, tt.path)
			if rule == nil {
				t.Fatalf("expected rule to match Azure-OpenAI for host=%q path=%q, got nil", tt.host, tt.path)
			}
			if rule.Name != "Azure-OpenAI" {
				t.Errorf("rule.Name=%q want %q", rule.Name, "Azure-OpenAI")
			}
		})
	}
}

func TestFindRule_WildcardNoMatch(t *testing.T) {
	tests := []struct {
		name string
		host string
		path string
	}{
		{
			name: "evil domain wrapping azure suffix",
			host: "evil.com.openai.azure.com.evil.com",
			path: "/openai/deployments/gpt4/chat/completions",
		},
		{
			name: "openai.azure.com without subdomain",
			host: "openai.azure.com",
			path: "/openai/deployments/gpt4/chat/completions",
		},
		{
			name: "unknown host with azure path",
			host: "notazure.example.com",
			path: "/openai/deployments/gpt4/chat/completions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := findRule(tt.host, tt.path)
			if rule != nil && rule.Name == "Azure-OpenAI" {
				t.Errorf("host=%q should NOT match Azure-OpenAI wildcard rule", tt.host)
			}
		})
	}
}

func TestFindRule_PortStripping(t *testing.T) {
	// ポート番号付きホストでもマッチすること
	rule := findRule("api.githubcopilot.com:443", "/chat/completions")
	if rule == nil {
		t.Fatal("expected rule to match with port in host, got nil")
	}
	if rule.Name != "GitHub-Copilot" {
		t.Errorf("rule.Name=%q want %q", rule.Name, "GitHub-Copilot")
	}
}

func TestFindRule_NoMatch(t *testing.T) {
	tests := []struct {
		name string
		host string
		path string
	}{
		{"unknown host", "example.com", "/api/chat"},
		{"wrong path on copilot host", "api.githubcopilot.com", "/v1/models"},
		{"wrong path on openai host", "api.openai.com", "/v1/models"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := findRule(tt.host, tt.path)
			if rule != nil {
				t.Errorf("host=%q path=%q should not match any rule, got %q", tt.host, tt.path, rule.Name)
			}
		})
	}
}

func TestExtractGeminiWeb_WithFileAttachment(t *testing.T) {
	// Simulate a Gemini payload where file content is embedded alongside the
	// user text. payload[0] = [userText, null, null, null, [[fileContent, "text/plain", ...]]]
	fileContent := "export AWS_ACCESS_KEY_ID=\"AKIAIOSFODNN7EXAMPLE\"\nexport AWS_SECRET_ACCESS_KEY=\"wJalrXUtnFEMI/K7MDENG/bPxRfiCY\""
	userText := "このファイルを確認して"

	payloadInner := []interface{}{
		userText,
		nil, nil, nil,
		[]interface{}{
			[]interface{}{
				[]interface{}{fileContent, "text/plain", nil, "creds.txt"},
			},
		},
	}
	payloadJSON, _ := json.Marshal([]interface{}{payloadInner})
	fReq, _ := json.Marshal([]interface{}{nil, string(payloadJSON)})

	formBody := "f.req=" + url.QueryEscape(string(fReq))
	got, err := extractGeminiWeb([]byte(formBody))
	if err != nil {
		t.Fatalf("extractGeminiWeb error: %v", err)
	}
	if !strings.Contains(got, "AWS_ACCESS_KEY_ID") {
		t.Errorf("file content not found in extracted text: %q", got)
	}
	if !strings.Contains(got, userText) {
		t.Errorf("user text not found in extracted text: %q", got)
	}
}

func TestCheckSensitiveFilename(t *testing.T) {
	makeMultipart := func(filename, content string) []byte {
		boundary := "TestBoundary1234"
		body := "--" + boundary + "\r\n" +
			`Content-Disposition: form-data; name="file"; filename="` + filename + `"` + "\r\n" +
			"Content-Type: text/plain\r\n\r\n" +
			content + "\r\n" +
			"--" + boundary + "--\r\n"
		return []byte(body)
	}

	tests := []struct {
		filename    string
		wantRuleID  string
		wantTrigger bool
	}{
		{"id_rsa", "FILE-001", true},
		{"id_ed25519", "FILE-001", true},
		{"production.env", "FILE-002", true},
		{".env", "FILE-002", true},
		{"server.pem", "FILE-003", true},
		{"private.key", "FILE-003", true},
		{"keystore.p12", "FILE-003", true},
		{"credentials", "FILE-004", true},
		{"credentials.json", "FILE-004", true},
		{"service-account.json", "FILE-005", true},
		{"terraform.tfvars", "FILE-006", true},
		{"secrets.yaml", "FILE-007", true},
		{"kubeconfig", "FILE-008", true},
		// non-sensitive filenames should not trigger
		{"report.pdf", "", false},
		{"notes.txt", "", false},
		{"image.png", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			body := makeMultipart(tt.filename, "content")
			fname, ruleID, _ := checkSensitiveFilename(body)
			if tt.wantTrigger {
				if fname == "" {
					t.Errorf("expected match for filename %q but got none", tt.filename)
				}
				if ruleID != tt.wantRuleID {
					t.Errorf("ruleID=%q want %q for filename %q", ruleID, tt.wantRuleID, tt.filename)
				}
			} else {
				if fname != "" {
					t.Errorf("unexpected match for filename %q: ruleID=%q", tt.filename, ruleID)
				}
			}
		})
	}
}

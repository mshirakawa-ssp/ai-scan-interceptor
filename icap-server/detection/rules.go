package detection

import (
	"regexp"
	"strings"
)

// RuleMatch records a single alert rule hit.
type RuleMatch struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Excerpt     string `json:"excerpt"` // matched text (truncated, may contain sensitive data)
}

// alertRule defines one pattern-based detection rule.
type alertRule struct {
	ID              string
	Severity        string
	Description     string
	Pattern         *regexp.Regexp
	// NegativeContext: if any pattern matches within ±150 chars of the hit, suppress.
	NegativeContext []*regexp.Regexp
	// ScanBody: if true, scan raw JSON body in addition to extracted prompt.
	ScanBody bool
	// MaskBody: if true, MaskSensitive will replace matches in the raw body.
	// Set to false for keyword-only rules whose pattern matches JSON key names
	// (e.g. `\bpassword\b`) to avoid corrupting JSON structure.
	MaskBody bool
	// MaskReplacement is the replacement string used when MaskBody is true.
	// Supports $1, ${1} backreferences to preserve key names (e.g. "${1}[REDACTED]").
	// Defaults to "[REDACTED]" when empty.
	MaskReplacement string
}

// match returns (matched, excerpt). excerpt is the text around the match.
func (r *alertRule) match(text string) (bool, string) {
	loc := r.Pattern.FindStringIndex(text)
	if loc == nil {
		return false, ""
	}
	// Evaluate negative context in a window around the match
	start := loc[0] - 150
	if start < 0 {
		start = 0
	}
	end := loc[1] + 150
	if end > len(text) {
		end = len(text)
	}
	window := text[start:end]
	for _, neg := range r.NegativeContext {
		if neg.MatchString(window) {
			return false, ""
		}
	}
	// Build a short excerpt around the match
	exStart := loc[0] - 20
	if exStart < 0 {
		exStart = 0
	}
	exEnd := loc[1] + 20
	if exEnd > len(text) {
		exEnd = len(text)
	}
	excerpt := strings.TrimSpace(text[exStart:exEnd])
	return true, excerpt
}

// builtinRules are evaluated against every captured AI prompt (and raw body for ScanBody rules).
var builtinRules = []alertRule{
	// ---- Critical: explicit credential strings ----
	{
		ID:          "CRED-001",
		Severity:    "critical",
		Description: "OpenAI API key",
		// sk- followed by project/user key formats
		Pattern:  regexp.MustCompile(`sk-(?:proj|org)?-?[a-zA-Z0-9\-_]{20,}`),
		ScanBody: true,
		MaskBody: true,
	},
	{
		ID:          "CRED-002",
		Severity:    "critical",
		Description: "Anthropic API key",
		Pattern:     regexp.MustCompile(`sk-ant-api\d{2}-[a-zA-Z0-9\-_]{20,}`),
		ScanBody:    true,
		MaskBody:    true,
	},
	{
		ID:          "CRED-003",
		Severity:    "critical",
		Description: "AWS Access Key ID",
		// AKIA = permanent IAM key, ASIA = temporary STS key, AROA/AIDA/ANPA/ANVA/AIPA = other AWS IDs
		Pattern:  regexp.MustCompile(`(?:AKIA|ASIA|AROA|AIDA|ANPA|ANVA|AIPA)[0-9A-Z]{16}`),
		ScanBody: true,
		MaskBody: true,
	},
	{
		ID:          "CRED-004",
		Severity:    "critical",
		Description: "AWS Secret Access Key",
		// Group 1 captures key name + assignment so only the value is replaced.
		Pattern:         regexp.MustCompile(`(?i)(aws[_\-\s]{0,5}secret[_\-\s]{0,5}(?:access[_\-\s]{0,5})?key\s*[=:]\s*(?:\\?")?)[A-Za-z0-9+/]{20,}`),
		ScanBody:        true,
		MaskBody:        true,
		MaskReplacement: "${1}[REDACTED]",
	},
	{
		ID:          "CRED-005",
		Severity:    "critical",
		Description: "GitHub personal access token",
		Pattern:     regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`),
		ScanBody:    true,
		MaskBody:    true,
	},
	{
		ID:          "CRED-006",
		Severity:    "critical",
		Description: "Google API key",
		Pattern:     regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		ScanBody:    true,
		MaskBody:    true,
	},
	{
		ID:          "CRED-007",
		Severity:    "critical",
		Description: "PEM private key",
		Pattern:     regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		ScanBody:    true,
		MaskBody:    true,
	},
	{
		ID:          "CRED-008",
		Severity:    "critical",
		Description: "JWT bearer token",
		// eyJ<header>.eyJ<payload>.<sig>
		Pattern:  regexp.MustCompile(`eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.`),
		ScanBody: true,
		MaskBody: true,
	},
	{
		ID:          "CRED-009",
		Severity:    "critical",
		Description: "AWS Session Token",
		// Group 1 captures key name + assignment so only the value is replaced.
		Pattern:         regexp.MustCompile(`(?i)((?:aws_session_token|x-amz-security-token)\s*[=:]\s*(?:\\?")?)[A-Za-z0-9+/=]{50,}`),
		ScanBody:        true,
		MaskBody:        true,
		MaskReplacement: "${1}[REDACTED]",
	},

	// ---- High: credential-in-value patterns ----
	{
		ID:          "CRED-101",
		Severity:    "high",
		Description: "Credential key-value assignment",
		// e.g. password=hunter2, api_key: sk-..., secret: abc
		// Group 1 captures key + assignment operator so only the value is replaced.
		Pattern: regexp.MustCompile(`(?i)((?:password|passwd|secret|api[_\-]?key|access[_\-]?token|auth[_\-]?token|private[_\-]?key)\s*[:=]\s*)\S{4,}`),
		// Suppress when it looks like documentation, examples, or config templates
		NegativeContext: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(how[_ ]to|example|sample|placeholder|<[a-z_]+>|\[your|{your|your_[a-z]|\$\{|:= ""|\s""$|\s''$)`),
		},
		ScanBody:        true,
		MaskBody:        true,
		MaskReplacement: "${1}[REDACTED]",
	},
	{
		ID:          "PII-101",
		Severity:    "high",
		Description: "Japanese confidentiality markers",
		Pattern:     regexp.MustCompile(`機密|社外秘|極秘|秘密情報`),
		// MaskBody: false — these are natural-language labels, not structured values;
		// masking them in the body does not help and can break readable text unexpectedly.
	},
	{
		ID:          "PII-102",
		Severity:    "high",
		Description: "Credit/debit card number",
		// Visa, Mastercard, Amex, Discover (Luhn not checked, rely on format)
		Pattern:  regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`),
		ScanBody: true,
		MaskBody: true,
	},
	{
		ID:          "PII-103",
		Severity:    "high",
		Description: "Japanese My Number (個人番号)",
		// 12-digit number in a context that implies personal number
		Pattern: regexp.MustCompile(`(?i)(マイナンバー|個人番号|my.?number)\s*[：:是]?\s*\d[\d\-\s]{10,14}\d`),
		MaskBody: true,
	},

	// ---- Medium: contextual keyword patterns (with false-positive suppression) ----
	{
		ID:          "KEYWORD-201",
		Severity:    "medium",
		Description: "Password in disclosure context",
		Pattern:     regexp.MustCompile(`(?i)\bpassword\b`),
		// Suppress for technical/educational mentions
		NegativeContext: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(how (to|do|can|should)|what is|validate|validation|minimum.{0,20}length|policy|example|sample|forgot|reset (your|my|the)|create.{0,10}password|password (strength|hint|recovery|manager|field|input|policy|hash|encrypt|check|require)|set.{0,5}password\s*$)`),
		},
		// MaskBody: false — `\bpassword\b` matches JSON key names (e.g. "password":"...")
		// and replacing the key would corrupt JSON structure. The actual credential
		// value is already covered by CRED-101 which matches the full key=value pair.
	},
	{
		ID:          "KEYWORD-202",
		Severity:    "medium",
		Description: "Internal-use or confidential label",
		Pattern:     regexp.MustCompile(`(?i)(internal use only|社内限り|confidential -|for internal)`),
		// MaskBody: false — these are multi-word natural-language labels unlikely to
		// appear as structured credential values; masking adds noise without security benefit.
	},
	{
		ID:          "KEYWORD-203",
		Severity:    "medium",
		Description: "Authentication token in context",
		Pattern:     regexp.MustCompile(`(?i)\b(bearer|auth|authorization)\s+[a-zA-Z0-9\-_+/]{16,}`),
		ScanBody:    true,
		MaskBody:    true,
	},
}

// severityOrder maps severity string to integer for comparison.
var severityOrder = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
}

// highestSeverity returns the more severe of two severity strings.
func highestSeverity(a, b string) string {
	if severityOrder[a] >= severityOrder[b] {
		return a
	}
	return b
}

// Package detection identifies AI service API requests and extracts prompts.
package detection

import (
	"log"
	"strings"
)

// Result holds the extracted information from one AI API call.
type Result struct {
	Service      string
	Prompt       string
	Triggered    bool   // true if any alert rule matched
	Severity     string // highest severity from alert rules ("critical"|"high"|"medium"|"low"|"")
	RuleMatches  []RuleMatch
	IsFileUpload bool   // true when the request body was a multipart file upload
}

// Detector matches incoming HTTP requests against known AI service patterns.
// The struct is kept for API compatibility; rule state is managed via ActiveRules().
type Detector struct{}

// NewDetector creates a Detector.
func NewDetector() *Detector {
	return &Detector{}
}

// Detect attempts to identify and extract a prompt from the HTTP request.
// Returns (result, true) on success, (nil, false) if not an AI request or no prompt found.
func (d *Detector) Detect(host, path, method string, body []byte) (*Result, bool) {
	if method != "POST" && method != "PUT" && method != "PATCH" {
		return nil, false
	}

	isFileUpload := len(body) > 2 && body[0] == '-' && body[1] == '-'

	rule := findRule(host, path)

	// Fallback: if no path-specific rule matched but the body is a multipart upload
	// and the host belongs to a known AI service, still apply filename screening and
	// content scanning. This catches file upload endpoints that differ from chat paths
	// (e.g. Gemini's upload paths that are separate from /_/BardChatUi/StreamGenerate).
	if rule == nil {
		if isFileUpload && isKnownAIHost(host) {
			return d.detectMultipartUpload(host, body)
		}
		return nil, false
	}

	prompt, err := rule.Extract(body)
	if err != nil {
		log.Printf("[detect] extract error rule=%s: %v (body_prefix=%q)", rule.Name, err, truncateBytes(body, 200))
		return nil, false
	}
	if strings.TrimSpace(prompt) == "" {
		log.Printf("[detect] empty prompt from rule=%s (body_prefix=%q)", rule.Name, truncateBytes(body, 200))
		return nil, false
	}

	result := &Result{
		Service:      rule.Name,
		Prompt:       prompt,
		IsFileUpload: isFileUpload,
	}

	// --- Active alert rules (builtin + custom, managed via ActiveRules()) ---
	// Scan only the extracted prompt (last user message). Scanning the raw body
	// causes false positives because assistant turns may quote previously-detected
	// credential values (e.g. a CRED-003 explanation that echoes the AKIA key).
	promptStr := prompt
	activeRules := ActiveRules()
	for i := range activeRules {
		r := &activeRules[i]
		if matched, excerpt := r.match(promptStr); matched {
			result.Triggered = true
			result.RuleMatches = append(result.RuleMatches, RuleMatch{
				RuleID:      r.ID,
				Severity:    r.Severity,
				Description: r.Description,
				Excerpt:     excerpt,
			})
		}
	}

	// --- Filename screening for file uploads ---
	// Check uploaded filenames against known sensitive patterns regardless of content.
	// This catches cases where the file type is encrypted or otherwise unreadable.
	if isFileUpload {
		if fname, ruleID, desc := checkSensitiveFilename(body); fname != "" {
			result.Triggered = true
			result.RuleMatches = append(result.RuleMatches, RuleMatch{
				RuleID:      ruleID,
				Severity:    "high",
				Description: desc,
				Excerpt:     fname,
			})
			log.Printf("[detect] sensitive filename blocked: rule=%s filename=%q", ruleID, fname)
		}
	}

	// --- Gemini opaque file attachment detection ---
	// Gemini Web uploads files to Google's internal contrib_service before the chat
	// request is sent. The StreamGenerate payload only contains a URL token like
	// "/contrib_service/ttl_1d/<hash>" — the file content is never visible to the proxy.
	// Block any StreamGenerate request that references a file attachment, since we
	// cannot scan the content. This is a fail-safe: unknown content = block.
	if result.Service == "Gemini-Web" {
		if ref := extractGeminiContribRef(promptStr); ref != "" {
			result.IsFileUpload = true
			result.Triggered = true
			result.RuleMatches = append(result.RuleMatches, RuleMatch{
				RuleID:      "FILE-009",
				Severity:    "high",
				Description: "Gemini file attachment (content encrypted/opaque; cannot be scanned)",
				Excerpt:     ref,
			})
			log.Printf("[detect] Gemini opaque file attachment: ref=%q", ref)
		}
	}

	// --- Compute highest severity ---
	result.Severity = computeSeverity(result)

	// Truncate stored prompt after all matching is done so keywords at the end of
	// long prompts (e.g., after a <system-reminder> injection) are never missed.
	const maxPromptLen = 4096
	if len(result.Prompt) > maxPromptLen {
		result.Prompt = result.Prompt[:maxPromptLen] + "… [truncated]"
	}

	return result, true
}

// detectMultipartUpload handles multipart file uploads to AI services whose
// upload path doesn't match any chat-specific rule (e.g. Gemini's separate
// upload endpoints). It applies filename screening and content scanning and
// returns a synthetic "FileUpload" result so that policy enforcement can act on it.
func (d *Detector) detectMultipartUpload(host string, body []byte) (*Result, bool) {
	serviceName := knownAIServiceName(host)
	log.Printf("[detect] multipart fallback: host=%s service=%s body=%d", host, serviceName, len(body))

	result := &Result{
		Service:      serviceName,
		Prompt:       "",
		IsFileUpload: true,
	}

	// Filename screening (works even when content is encrypted).
	if fname, ruleID, desc := checkSensitiveFilename(body); fname != "" {
		result.Triggered = true
		result.Prompt = "[file: " + fname + "]"
		result.RuleMatches = append(result.RuleMatches, RuleMatch{
			RuleID:      ruleID,
			Severity:    "high",
			Description: desc,
			Excerpt:     fname,
		})
		log.Printf("[detect] sensitive filename (fallback): rule=%s filename=%q service=%s", ruleID, fname, serviceName)
	}

	// Content scanning for plain-text file parts.
	if text, err := extractMultipartFile(body); err == nil && strings.TrimSpace(text) != "" {
		if result.Prompt == "" {
			result.Prompt = text
		}
		activeRules := ActiveRules()
		for i := range activeRules {
			r := &activeRules[i]
			if matched, excerpt := r.match(text); matched {
				result.Triggered = true
				result.RuleMatches = append(result.RuleMatches, RuleMatch{
					RuleID:      r.ID,
					Severity:    r.Severity,
					Description: r.Description,
					Excerpt:     excerpt,
				})
			}
		}
	}

	if result.Prompt == "" {
		return nil, false
	}
	result.Severity = computeSeverity(result)
	const maxPromptLen = 4096
	if len(result.Prompt) > maxPromptLen {
		result.Prompt = result.Prompt[:maxPromptLen] + "… [truncated]"
	}
	return result, true
}

// isKnownAIHost returns true if host belongs to any known AI service.
func isKnownAIHost(host string) bool {
	if idx := strings.LastIndexByte(host, ':'); idx >= 0 {
		host = host[:idx]
	}
	return knownAIServiceName(host) != "Unknown"
}

// knownAIServiceName maps a host to a human-readable service name.
// Returns "Unknown" if not recognized.
func knownAIServiceName(host string) string {
	if idx := strings.LastIndexByte(host, ':'); idx >= 0 {
		host = host[:idx]
	}
	// Check against all service rule hosts first.
	for i := range rules {
		r := &rules[i]
		for _, h := range r.Hosts {
			if strings.HasPrefix(h, "*.") {
				if strings.HasSuffix(host, h[1:]) {
					return r.Name
				}
			} else if h == host {
				return r.Name
			}
		}
	}
	// Additional upload/storage domains not covered by chat rules.
	switch {
	case strings.HasSuffix(host, ".googleapis.com"):
		return "Gemini"
	case strings.HasSuffix(host, ".openai.com"):
		return "ChatGPT"
	case strings.HasSuffix(host, ".anthropic.com"):
		return "Claude-API"
	case strings.HasSuffix(host, ".microsoft.com") || strings.HasSuffix(host, ".bing.com"):
		return "Copilot"
	}
	return "Unknown"
}

func truncateBytes(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}

// computeSeverity returns the highest severity from rule matches.
func computeSeverity(r *Result) string {
	sev := ""
	for _, rm := range r.RuleMatches {
		sev = highestSeverity(sev, rm.Severity)
	}
	return sev
}

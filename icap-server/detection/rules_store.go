package detection

import (
	"encoding/json"
	"log"
	"os"
	"regexp"
	"sync"
)

// RuleEntry is the JSON-serializable form of a detection rule.
type RuleEntry struct {
	ID              string   `json:"id"`
	Source          string   `json:"source"`             // "builtin" or "custom"
	Enabled         bool     `json:"enabled"`
	Severity        string   `json:"severity"`
	Description     string   `json:"description"`
	Pattern         string   `json:"pattern"`
	NegativeContext []string `json:"negative_context,omitempty"`
	MaskBody        bool     `json:"mask_body"`
	// MaskReplacement is the replacement string for body masking.
	// Supports $1 backreferences to preserve key names (e.g. "${1}[REDACTED]").
	// Empty means "[REDACTED]" (replace full match).
	MaskReplacement string `json:"mask_replacement,omitempty"`
}

// DefaultEntries serializes builtinRules to []RuleEntry.
func DefaultEntries() []RuleEntry {
	entries := make([]RuleEntry, 0, len(builtinRules))
	for _, r := range builtinRules {
		e := RuleEntry{
			ID:              r.ID,
			Source:          "builtin",
			Enabled:         true,
			Severity:        r.Severity,
			Description:     r.Description,
			Pattern:         r.Pattern.String(),
			MaskBody:        r.MaskBody,
			MaskReplacement: r.MaskReplacement,
		}
		if len(r.NegativeContext) > 0 {
			e.NegativeContext = make([]string, len(r.NegativeContext))
			for i, nc := range r.NegativeContext {
				e.NegativeContext[i] = nc.String()
			}
		}
		entries = append(entries, e)
	}
	return entries
}

// SeedRulesFile writes DefaultEntries to path as JSON if the file does NOT exist.
func SeedRulesFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil // file already exists
	}
	return SaveRulesFile(path, DefaultEntries())
}

// LoadRulesFile reads and parses a rules JSON file.
func LoadRulesFile(path string) ([]RuleEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var entries []RuleEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// EntriesToAlertRules compiles enabled RuleEntry records into []alertRule.
// Entries with Enabled=false or invalid patterns are skipped (bad patterns are logged).
func EntriesToAlertRules(entries []RuleEntry) []alertRule {
	rules := make([]alertRule, 0, len(entries))
	for _, e := range entries {
		if !e.Enabled {
			continue
		}
		re, err := regexp.Compile(e.Pattern)
		if err != nil {
			log.Printf("[rules-store] skipping rule %q: bad pattern: %v", e.ID, err)
			continue
		}
		r := alertRule{
			ID:              e.ID,
			Severity:        e.Severity,
			Description:     e.Description,
			Pattern:         re,
			MaskBody:        e.MaskBody,
			MaskReplacement: e.MaskReplacement,
		}
		for _, ncStr := range e.NegativeContext {
			ncRe, err := regexp.Compile(ncStr)
			if err != nil {
				log.Printf("[rules-store] skipping negative context for rule %q: bad pattern: %v", e.ID, err)
				continue
			}
			r.NegativeContext = append(r.NegativeContext, ncRe)
		}
		rules = append(rules, r)
	}
	return rules
}

// SaveRulesFile marshals entries and writes them to path with 0600 permissions.
func SaveRulesFile(path string, entries []RuleEntry) error {
	out, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0600)
}

// activeStore is the global active rules store, updated by the reloader.
var activeStore struct {
	sync.RWMutex
	rules []alertRule
}

// ActiveRules returns the currently active alert rules.
func ActiveRules() []alertRule {
	activeStore.RLock()
	defer activeStore.RUnlock()
	return activeStore.rules
}

// SetActiveRules replaces the active alert rules.
func SetActiveRules(rules []alertRule) {
	activeStore.Lock()
	defer activeStore.Unlock()
	activeStore.rules = rules
}

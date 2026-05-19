package detection

import (
	"log"
	"os"
	"time"
)

// StartRulesReloader polls the given rules.json path every 5 seconds and
// calls SetActiveRules whenever the file's modification time changes.
func StartRulesReloader(path string) {
	go func() {
		var lastMod time.Time
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			info, err := os.Stat(path)
			if err != nil {
				if !os.IsNotExist(err) {
					log.Printf("[rules-reloader] stat error: %v", err)
				}
				continue
			}
			if !info.ModTime().After(lastMod) {
				continue // unchanged
			}
			entries, err := LoadRulesFile(path)
			if err != nil {
				log.Printf("[rules-reloader] reload error: %v", err)
				continue
			}
			rules := EntriesToAlertRules(entries)
			SetActiveRules(rules)
			lastMod = info.ModTime()
			log.Printf("[rules-reloader] reloaded %d rule(s) from %s", len(rules), path)
		}
	}()
}

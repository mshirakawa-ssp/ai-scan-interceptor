package notification

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"
)

// FileConfig holds notification settings loaded from notification.json.
type FileConfig struct {
	SlackWebhookURL string   `json:"slack_webhook_url"`
	SMTPHost        string   `json:"smtp_host"`
	SMTPPort        string   `json:"smtp_port"`
	SMTPUser        string   `json:"smtp_user"`
	SMTPPass        string   `json:"smtp_pass"`
	SMTPFrom        string   `json:"smtp_from"`
	AlertEmailTo    []string `json:"alert_email_to"`
}

// ConfigStore is a thread-safe hot-reloading store for notification config.
type ConfigStore struct {
	mu   sync.RWMutex
	path string
	cfg  FileConfig
}

// LoadConfigStore reads notification.json and starts a 5s reload goroutine.
// If the file does not exist, an empty (disabled) config is used.
func LoadConfigStore(path string) *ConfigStore {
	cs := &ConfigStore{path: path}
	cs.tryLoad()
	go cs.reloader()
	return cs
}

func (cs *ConfigStore) Get() FileConfig {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.cfg
}

func (cs *ConfigStore) tryLoad() {
	data, err := os.ReadFile(cs.path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[notification/config] read error: %v", err)
		}
		return
	}
	var cfg FileConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("[notification/config] parse error: %v", err)
		return
	}
	cs.mu.Lock()
	cs.cfg = cfg
	cs.mu.Unlock()
}

func (cs *ConfigStore) reloader() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for range t.C {
		cs.tryLoad()
	}
}

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// NotificationSettings holds Slack/email alert configuration.
type NotificationSettings struct {
	SlackWebhookURL string   `json:"slack_webhook_url"`
	SMTPHost        string   `json:"smtp_host"`
	SMTPPort        string   `json:"smtp_port"`
	SMTPUser        string   `json:"smtp_user"`
	SMTPPass        string   `json:"smtp_pass"`
	SMTPFrom        string   `json:"smtp_from"`
	AlertEmailTo    []string `json:"alert_email_to"`
}

const passwordMask = "***"

// NotificationSettingsStore is a thread-safe, file-backed notification config store.
type NotificationSettingsStore struct {
	mu   sync.RWMutex
	path string
	s    NotificationSettings
}

func newNotificationSettingsStore(path string) (*NotificationSettingsStore, error) {
	st := &NotificationSettingsStore{
		path: path,
		s:    NotificationSettings{SMTPPort: "587"},
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return st, nil
		}
		return nil, fmt.Errorf("load notification settings: %w", err)
	}
	if err := json.Unmarshal(data, &st.s); err != nil {
		return nil, fmt.Errorf("parse notification settings: %w", err)
	}
	return st, nil
}

// GetMasked returns settings safe for API responses — SMTP password replaced with "***".
func (st *NotificationSettingsStore) GetMasked() NotificationSettings {
	st.mu.RLock()
	defer st.mu.RUnlock()
	cp := st.s
	if cp.SMTPPass != "" {
		cp.SMTPPass = passwordMask
	}
	return cp
}

// Set saves new settings. If SMTPPass == "***", the existing password is kept.
func (st *NotificationSettingsStore) Set(n NotificationSettings) error {
	if n.SMTPPort == "" {
		n.SMTPPort = "587"
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if n.SMTPPass == passwordMask {
		n.SMTPPass = st.s.SMTPPass
	}
	data, err := json.MarshalIndent(n, "", "  ")
	if err != nil {
		return err
	}
	st.s = n
	return os.WriteFile(st.path, data, 0600)
}

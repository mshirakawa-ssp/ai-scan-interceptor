// Package notification dispatches alerts via Slack webhook and/or SMTP email.
package notification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// Notifier dispatches alerts through one or more channels (Slack webhook, email).
type Notifier struct {
	webhookURL string
	email      *EmailNotifier
	httpClient *http.Client

	// dynamic config (hot-reloaded from notification.json); nil = static mode
	store      *ConfigStore
	envWebhook string
	envEmail   EmailConfig
}

// NewNotifier builds a Notifier from static configuration.
// Either or both channels may be inactive (empty webhookURL / nil email).
func NewNotifier(webhookURL string, email *EmailNotifier) *Notifier {
	return &Notifier{
		webhookURL: webhookURL,
		email:      email,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// NewDynamicNotifier builds a Notifier that reads from a hot-reloaded ConfigStore
// on every Send call. env* values are used as fallbacks when the file config is empty.
func NewDynamicNotifier(store *ConfigStore, envEmail EmailConfig, envWebhook string) *Notifier {
	return &Notifier{
		store:      store,
		envWebhook: envWebhook,
		envEmail:   envEmail,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// resolveConfig returns effective webhook URL and email notifier for a Send call.
func (n *Notifier) resolveConfig() (string, *EmailNotifier) {
	if n.store == nil {
		return n.webhookURL, n.email
	}
	cfg := n.store.Get()

	webhook := cfg.SlackWebhookURL
	if webhook == "" {
		webhook = n.envWebhook
	}

	emailCfg := EmailConfig{
		Host:     firstNonEmpty(cfg.SMTPHost, n.envEmail.Host),
		Port:     firstNonEmpty(cfg.SMTPPort, n.envEmail.Port, "587"),
		User:     firstNonEmpty(cfg.SMTPUser, n.envEmail.User),
		Password: firstNonEmpty(cfg.SMTPPass, n.envEmail.Password),
		From:     firstNonEmpty(cfg.SMTPFrom, n.envEmail.From),
		To:       nonEmptySlice(cfg.AlertEmailTo, n.envEmail.To),
	}
	return webhook, NewEmailNotifier(emailCfg)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func nonEmptySlice(a, b []string) []string {
	if len(a) > 0 {
		return a
	}
	return b
}

// Send dispatches an alert for entry to all configured channels asynchronously.
// entry must be JSON-marshallable (e.g. storage.LogEntry).
func (n *Notifier) Send(entry interface{}) {
	raw, err := json.Marshal(entry)
	if err != nil {
		log.Printf("[notifier] marshal: %v", err)
		return
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		log.Printf("[notifier] unmarshal: %v", err)
		return
	}

	webhookURL, email := n.resolveConfig()
	if webhookURL != "" {
		go n.sendSlackURL(webhookURL, m)
	}
	if email != nil {
		go n.sendEmail(m)
	}
}

// ---- Slack ----

func (n *Notifier) sendSlackURL(webhookURL string, m map[string]interface{}) {
	prompt := str(m["prompt"])
	if len(prompt) > 200 {
		prompt = prompt[:200] + "…"
	}

	payload := map[string]interface{}{
		"text": "[AI-Scan-Interceptor] Sensitive Prompt Detected",
		"blocks": []map[string]interface{}{
			{
				"type": "header",
				"text": map[string]string{"type": "plain_text", "text": "AI-Scan-Interceptor Alert"},
			},
			{
				"type": "section",
				"fields": []map[string]string{
					{"type": "mrkdwn", "text": "*Service:*\n" + str(m["service"])},
					{"type": "mrkdwn", "text": "*Host:*\n" + str(m["host"])},
					{"type": "mrkdwn", "text": "*Client IP:*\n" + str(m["client_ip"])},
					{"type": "mrkdwn", "text": "*Keywords:*\n" + str(m["keywords"])},
					{"type": "mrkdwn", "text": "*Time:*\n" + str(m["timestamp"])},
				},
			},
			{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": "*Prompt excerpt:*\n```" + prompt + "```",
				},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[notifier/slack] marshal: %v", err)
		return
	}

	resp, err := n.httpClient.Post(webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("[notifier/slack] post: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Printf("[notifier/slack] HTTP %d", resp.StatusCode)
	} else {
		log.Printf("[notifier/slack] sent service=%s", str(m["service"]))
	}
}

// ---- Email ----

func (n *Notifier) sendEmail(m map[string]interface{}) {
	subject := fmt.Sprintf("[AI-Scan-Interceptor] Alert: %s keyword detected (%s)",
		str(m["keywords"]), str(m["service"]))

	prompt := str(m["prompt"])
	if len(prompt) > 500 {
		prompt = prompt[:500] + "\n… [truncated]"
	}

	body := strings.Join([]string{
		"AI-Scan-Interceptor — Sensitive Prompt Detected",
		strings.Repeat("─", 50),
		"Service   : " + str(m["service"]),
		"Host      : " + str(m["host"]),
		"Path      : " + str(m["path"]),
		"Client IP : " + str(m["client_ip"]),
		"Keywords  : " + str(m["keywords"]),
		"Timestamp : " + str(m["timestamp"]),
		"",
		"Prompt excerpt:",
		"  " + strings.ReplaceAll(prompt, "\n", "\n  "),
		"",
		strings.Repeat("─", 50),
		"This alert was generated automatically by AI-Scan-Interceptor.",
	}, "\r\n")

	if err := n.email.Send(subject, body); err != nil {
		log.Printf("[notifier/email] send: %v", err)
	} else {
		log.Printf("[notifier/email] sent service=%s to=%v", str(m["service"]), n.email.cfg.To)
	}
}

func str(v interface{}) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

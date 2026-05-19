package notification

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// EmailConfig holds SMTP connection parameters.
type EmailConfig struct {
	Host     string // e.g. smtp.gmail.com
	Port     string // 587 (STARTTLS) or 465 (TLS)
	User     string // SMTP auth username
	Password string // SMTP auth password
	From     string // sender address
	To       []string // recipient addresses
}

// EmailNotifier sends alert emails via SMTP.
type EmailNotifier struct {
	cfg EmailConfig
}

// NewEmailNotifier returns nil (disabled) when cfg.Host is empty.
func NewEmailNotifier(cfg EmailConfig) *EmailNotifier {
	if cfg.Host == "" || len(cfg.To) == 0 {
		return nil
	}
	return &EmailNotifier{cfg: cfg}
}

// Send dispatches an alert email. Runs synchronously so callers should wrap in a goroutine.
func (e *EmailNotifier) Send(subject, body string) error {
	addr := net.JoinHostPort(e.cfg.Host, e.cfg.Port)

	msg := buildMIME(e.cfg.From, e.cfg.To, subject, body)

	auth := smtp.PlainAuth("", e.cfg.User, e.cfg.Password, e.cfg.Host)

	switch e.cfg.Port {
	case "465":
		return sendTLS(addr, e.cfg.Host, auth, e.cfg.From, e.cfg.To, msg)
	default: // 587 or 25 → STARTTLS
		return smtp.SendMail(addr, auth, e.cfg.From, e.cfg.To, msg)
	}
}

// sendTLS connects with implicit TLS (port 465).
func sendTLS(addr, host string, auth smtp.Auth, from string, to []string, msg []byte) error {
	tlsCfg := &tls.Config{ServerName: host}
	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("tls dial: %w", err)
	}
	defer conn.Close()

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer c.Quit()

	if err := c.Auth(auth); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, r := range to {
		if err := c.Rcpt(r); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	return w.Close()
}

// buildMIME constructs a minimal RFC 5322 message with UTF-8 plain-text body.
func buildMIME(from string, to []string, subject, body string) []byte {
	var sb strings.Builder
	sb.WriteString("From: " + from + "\r\n")
	sb.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	sb.WriteString("Subject: " + subject + "\r\n")
	sb.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(body)
	return []byte(sb.String())
}

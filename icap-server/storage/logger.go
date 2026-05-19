// Package storage handles persistent logging of captured AI prompts.
package storage

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LogEntry represents one captured AI prompt event.
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Service   string    `json:"service"`
	Host      string    `json:"host"`
	Path      string    `json:"path"`
	Prompt    string    `json:"prompt"`
	Triggered bool      `json:"triggered"`
	Severity  string    `json:"severity,omitempty"` // highest severity: critical|high|medium|low
	RuleIDs   []string  `json:"rule_ids,omitempty"` // matched alert rule IDs and descriptions
	ClientIP  string    `json:"client_ip"`
	UserID    string    `json:"user_id,omitempty"` // resolved identity (cert subject, hostname, JWT sub, …)
	// IdentitySource indicates how UserID was resolved.
	// Values: "mtls-cert" (X-User-Cert-Subject from tls-proxy / Squid),
	// "reverse-dns" (X-Client-IP → hostname), "jwt-sub" (Bearer JWT sub
	// claim, unverified), "ip-only" (no identity available, ClientIP only).
	// Empty string for legacy entries.
	IdentitySource string `json:"identity_source,omitempty"`
	Action         string `json:"action,omitempty"` // blocked|masked|warned|monitored|passed
}

// Logger writes LogEntry records as JSON Lines to a rotating log file.
type Logger struct {
	mu      sync.Mutex
	dir     string
	file    *os.File
	written int64
	maxSize int64
}

const defaultMaxSize = 10 << 20 // 10 MB

// NewLogger opens (or creates) a log file in dir.
func NewLogger(dir string) (*Logger, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	l := &Logger{dir: dir, maxSize: defaultMaxSize}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Logger) open() error {
	name := filepath.Join(l.dir, fmt.Sprintf("prompts_%s.jsonl", time.Now().UTC().Format("20060102_150405")))
	f, err := os.OpenFile(name, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	l.file = f
	l.written = 0
	log.Printf("[logger] writing to %s", name)
	return nil
}

// Write appends entry to the current log file, rotating if needed.
func (l *Logger) Write(entry LogEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.written+int64(len(data)) > l.maxSize {
		if err := l.rotate(); err != nil {
			return err
		}
	}

	n, err := l.file.Write(data)
	l.written += int64(n)
	return err
}

func (l *Logger) rotate() error {
	if l.file != nil {
		l.file.Close()
	}
	return l.open()
}

// Close flushes and closes the log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

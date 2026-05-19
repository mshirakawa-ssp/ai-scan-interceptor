package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const defaultRetentionDays = 30

// LogSettings holds WebUI-managed operational settings stored in settings.json.
type LogSettings struct {
	RetentionDays int `json:"retention_days"`
}

// LogSettingsStore is a thread-safe, file-backed store for log settings.
type LogSettingsStore struct {
	mu       sync.RWMutex
	path     string
	settings LogSettings
}

func newLogSettingsStore(path string) (*LogSettingsStore, error) {
	s := &LogSettingsStore{
		path:     path,
		settings: LogSettings{RetentionDays: defaultRetentionDays},
	}
	if err := s.load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("load log settings: %w", err)
	}
	return s, nil
}

func (s *LogSettingsStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.Unmarshal(data, &s.settings)
}

func (s *LogSettingsStore) Get() LogSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.settings
}

func (s *LogSettingsStore) Set(ls LogSettings) error {
	if ls.RetentionDays < 1 {
		ls.RetentionDays = 1
	}
	if ls.RetentionDays > 3650 {
		ls.RetentionDays = 3650
	}
	data, err := json.MarshalIndent(ls, "", "  ")
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settings = ls
	return os.WriteFile(s.path, data, 0600)
}

// RunLogCleanup runs a periodic goroutine that deletes JSONL log files older than RetentionDays.
// It runs once on startup then every 6 hours.
func RunLogCleanup(logDir string, store *LogSettingsStore) {
	run := func() {
		days := store.Get().RetentionDays
		cutoff := time.Now().AddDate(0, 0, -days)
		files, err := filepath.Glob(filepath.Join(logDir, "*.jsonl"))
		if err != nil {
			log.Printf("[cleanup] glob error: %v", err)
			return
		}
		deleted := 0
		for _, f := range files {
			info, err := os.Stat(f)
			if err != nil {
				continue
			}
			if info.ModTime().Before(cutoff) {
				if err := os.Remove(f); err == nil {
					deleted++
					log.Printf("[cleanup] removed old log: %s", filepath.Base(f))
				}
			}
		}
		if deleted > 0 {
			log.Printf("[cleanup] removed %d log file(s) older than %d days", deleted, days)
		}
	}

	go func() {
		run()
		for range time.Tick(6 * time.Hour) {
			run()
		}
	}()
}

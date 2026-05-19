package policy

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"
)

// Mode defines the enforcement mode for prompt inspection.
type Mode string

const (
	ModeMonitor Mode = "monitor" // ログのみ（通知なし）
	ModeWarn    Mode = "warn"    // ログ＋Webhook/メール通知（現状の動作）
	ModeBlock   Mode = "block"   // リクエストを 403 で拒否
	ModeMask    Mode = "mask"    // キーワードを [REDACTED] に置換して転送
)

// Policy holds the enforcement settings.
type Policy struct {
	GlobalMode   Mode            `json:"global_mode"`
	ServiceModes map[string]Mode `json:"service_modes,omitempty"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// Config is a thread-safe, file-backed policy store.
type Config struct {
	mu   sync.RWMutex
	data Policy
	path string
}

// Load loads a Config from the given file path.
// If the file does not exist, a default Policy (ModeMonitor) is created and
// written to disk so that later StartReloader ticks always find a valid file.
func Load(path string) (*Config, error) {
	c := &Config{path: path}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Create default policy file.
			c.data = Policy{
				GlobalMode: ModeMonitor,
				UpdatedAt:  time.Now().UTC(),
			}
			if writeErr := c.writeFile(); writeErr != nil {
				log.Printf("[policy] warning: could not write default policy file %s: %v", path, writeErr)
			}
			return c, nil
		}
		return nil, err
	}

	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	c.data = p
	return c, nil
}

// GetMode returns the effective Mode for the given service name.
// A per-service entry in ServiceModes takes precedence over GlobalMode.
func (c *Config) GetMode(service string) Mode {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if m, ok := c.data.ServiceModes[service]; ok {
		return m
	}
	return c.data.GlobalMode
}

// Set replaces the current policy and persists it to disk.
func (c *Config) Set(p Policy) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p.UpdatedAt = time.Now().UTC()
	c.data = p
	return c.writeFile()
}

// Get returns a snapshot of the current policy.
func (c *Config) Get() Policy {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.data
}

// StartReloader launches a goroutine that polls the backing file every 5 s
// and reloads it when the contents change.
func (c *Config) StartReloader() {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			data, err := os.ReadFile(c.path)
			if err != nil {
				if !os.IsNotExist(err) {
					log.Printf("[policy] reload error: %v", err)
				}
				continue
			}
			var p Policy
			if err := json.Unmarshal(data, &p); err != nil {
				log.Printf("[policy] reload parse error: %v", err)
				continue
			}
			c.mu.Lock()
			c.data = p
			c.mu.Unlock()
		}
	}()
}

// writeFile serialises and writes the current policy to disk (caller must hold mu).
func (c *Config) writeFile() error {
	data, err := json.MarshalIndent(c.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.path, data, 0600)
}

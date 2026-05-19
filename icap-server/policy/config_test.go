package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load returned nil config")
	}
	if cfg.data.GlobalMode != ModeMonitor {
		t.Errorf("GlobalMode=%q want %q", cfg.data.GlobalMode, ModeMonitor)
	}

	// ファイルが自動生成されていることを確認
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("default policy file should be created on disk")
	}
}

func TestLoadExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")

	p := Policy{
		GlobalMode: ModeBlock,
		ServiceModes: map[string]Mode{
			"ChatGPT": ModeWarn,
		},
		UpdatedAt: time.Now().UTC(),
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.data.GlobalMode != ModeBlock {
		t.Errorf("GlobalMode=%q want %q", cfg.data.GlobalMode, ModeBlock)
	}
	if m, ok := cfg.data.ServiceModes["ChatGPT"]; !ok || m != ModeWarn {
		t.Errorf("ServiceModes[ChatGPT]=%q want %q", m, ModeWarn)
	}
}

func TestGetMode_Global(t *testing.T) {
	tests := []struct {
		name       string
		globalMode Mode
		service    string
		want       Mode
	}{
		{"monitor mode", ModeMonitor, "ChatGPT", ModeMonitor},
		{"block mode", ModeBlock, "Gemini", ModeBlock},
		{"warn mode", ModeWarn, "Claude", ModeWarn},
		{"mask mode", ModeMask, "Azure-OpenAI", ModeMask},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "policy.json")
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			cfg.data.GlobalMode = tt.globalMode
			// ServiceModes が空の場合、GlobalMode が返ること
			cfg.data.ServiceModes = nil

			got := cfg.GetMode(tt.service)
			if got != tt.want {
				t.Errorf("GetMode(%q)=%q want %q", tt.service, got, tt.want)
			}
		})
	}
}

func TestGetMode_ServiceOverride(t *testing.T) {
	tests := []struct {
		name         string
		globalMode   Mode
		serviceName  string
		serviceMode  Mode
		queryService string
		want         Mode
	}{
		{
			name:         "service override takes precedence",
			globalMode:   ModeMonitor,
			serviceName:  "ChatGPT",
			serviceMode:  ModeBlock,
			queryService: "ChatGPT",
			want:         ModeBlock,
		},
		{
			name:         "other service falls back to global",
			globalMode:   ModeWarn,
			serviceName:  "ChatGPT",
			serviceMode:  ModeBlock,
			queryService: "Claude",
			want:         ModeWarn,
		},
		{
			name:         "mask override",
			globalMode:   ModeMonitor,
			serviceName:  "Azure-OpenAI",
			serviceMode:  ModeMask,
			queryService: "Azure-OpenAI",
			want:         ModeMask,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "policy.json")
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			cfg.data.GlobalMode = tt.globalMode
			cfg.data.ServiceModes = map[string]Mode{
				tt.serviceName: tt.serviceMode,
			}

			got := cfg.GetMode(tt.queryService)
			if got != tt.want {
				t.Errorf("GetMode(%q)=%q want %q", tt.queryService, got, tt.want)
			}
		})
	}
}

func TestSet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	newPolicy := Policy{
		GlobalMode: ModeBlock,
		ServiceModes: map[string]Mode{
			"ChatGPT": ModeMask,
			"Gemini":  ModeWarn,
		},
	}

	if err := cfg.Set(newPolicy); err != nil {
		t.Fatalf("Set returned error: %v", err)
	}

	// メモリ上のポリシーが更新されていること
	got := cfg.Get()
	if got.GlobalMode != ModeBlock {
		t.Errorf("GlobalMode=%q want %q", got.GlobalMode, ModeBlock)
	}
	if got.ServiceModes["ChatGPT"] != ModeMask {
		t.Errorf("ServiceModes[ChatGPT]=%q want %q", got.ServiceModes["ChatGPT"], ModeMask)
	}
	if got.ServiceModes["Gemini"] != ModeWarn {
		t.Errorf("ServiceModes[Gemini]=%q want %q", got.ServiceModes["Gemini"], ModeWarn)
	}
	// UpdatedAt が設定されていること
	if got.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should be set after Set()")
	}

	// ファイルに書き込まれていること
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	var written Policy
	if err := json.Unmarshal(data, &written); err != nil {
		t.Fatalf("unmarshal written file: %v", err)
	}
	if written.GlobalMode != ModeBlock {
		t.Errorf("written GlobalMode=%q want %q", written.GlobalMode, ModeBlock)
	}
	if written.ServiceModes["ChatGPT"] != ModeMask {
		t.Errorf("written ServiceModes[ChatGPT]=%q want %q", written.ServiceModes["ChatGPT"], ModeMask)
	}
}

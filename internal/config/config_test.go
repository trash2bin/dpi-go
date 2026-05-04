package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadValidTOML(t *testing.T) {
	t.Parallel()

	tomlContent := `
[app]
log_level = "debug"

[dns]
enabled = true
config_path = "/tmp/dpi-dns.conf"
reload_command = ["echo", "reload"]
blocked_domains = ["Example.com", "example.com", "rutracker.org"]

[firewall]
enabled = true
family = "inet"
table = "dpi"
chain = "input"
set_name = "blocked_ips"
blocked_ips = ["1.1.1.1", "8.8.8.8"]

[inspector]
enabled = true
queue_num = 10
fail_open = true
mode = "skeleton"
`

	path := writeTempFile(t, tomlContent)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.App.LogLevel != "debug" {
		t.Fatalf("unexpected log level: %q", cfg.App.LogLevel)
	}
	if got := len(cfg.DNS.BlockedDomains); got != 2 {
		t.Fatalf("unexpected blocked domains count: %d", got)
	}
	if cfg.Firewall.SetName != "blocked_ips" {
		t.Fatalf("unexpected firewall set name: %q", cfg.Firewall.SetName)
	}
	if cfg.Inspector.QueueNum != 10 {
		t.Fatalf("unexpected queue num: %d", cfg.Inspector.QueueNum)
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	t.Parallel()

	path := writeTempFile(t, `[dns]
enabled = false
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.App.LogLevel != "info" {
		t.Fatalf("unexpected default log level: %q", cfg.App.LogLevel)
	}
	if cfg.Firewall.Family != "inet" {
		t.Fatalf("unexpected default firewall family: %q", cfg.Firewall.Family)
	}
	if cfg.Inspector.Mode != "skeleton" {
		t.Fatalf("unexpected default inspector mode: %q", cfg.Inspector.Mode)
	}
}

func TestLoadInvalidTOML(t *testing.T) {
	t.Parallel()

	path := writeTempFile(t, `[dns]
enabled = "wrong"
`)
	if _, err := Load(path); err == nil {
		t.Fatal("Load() expected error for invalid TOML, got nil")
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "dpi.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}

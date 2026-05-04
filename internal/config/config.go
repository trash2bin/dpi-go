package config

import (
	"fmt"
	"net"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config is the main application configuration loaded from TOML.
type Config struct {
	App       AppConfig       `toml:"app"`
	DNS       DNSConfig       `toml:"dns"`
	Firewall  FirewallConfig  `toml:"firewall"`
	Inspector InspectorConfig `toml:"inspector"`
}

type AppConfig struct {
	LogLevel string `toml:"log_level"`
}

type DNSConfig struct {
	Enabled        bool     `toml:"enabled"`
	ConfigPath     string   `toml:"config_path"`
	ReloadCommand  []string `toml:"reload_command"`
	BlockedDomains []string `toml:"blocked_domains"`
}

type FirewallConfig struct {
	Enabled    bool     `toml:"enabled"`
	Family     string   `toml:"family"`
	Table      string   `toml:"table"`
	Chain      string   `toml:"chain"`
	SetName    string   `toml:"set_name"`
	BlockedIPs []string `toml:"blocked_ips"`
}

type InspectorConfig struct {
	Enabled  bool   `toml:"enabled"`
	QueueNum uint16 `toml:"queue_num"`
	FailOpen bool   `toml:"fail_open"`
	Mode     string `toml:"mode"`
}

// Default returns baseline config suitable for a local development run.
func Default() Config {
	return Config{
		App: AppConfig{
			LogLevel: "info",
		},
		DNS: DNSConfig{
			Enabled:        false,
			ConfigPath:     "/etc/dnsmasq.d/dpi.conf",
			ReloadCommand:  []string{"systemctl", "reload", "dnsmasq"},
			BlockedDomains: nil,
		},
		Firewall: FirewallConfig{
			Enabled:    false,
			Family:     "inet",
			Table:      "dpi",
			Chain:      "input",
			SetName:    "blocked_ips",
			BlockedIPs: nil,
		},
		Inspector: InspectorConfig{
			Enabled:  true,
			QueueNum: 0,
			FailOpen: true,
			Mode:     "skeleton",
		},
	}
}

// Load reads and validates TOML configuration.
func Load(path string) (Config, error) {
	cfg := Default()
	meta, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return Config{}, fmt.Errorf("decode TOML: %w", err)
	}

	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		parts := make([]string, 0, len(undecoded))
		for _, key := range undecoded {
			parts = append(parts, key.String())
		}
		return Config{}, fmt.Errorf("unknown TOML keys: %s", strings.Join(parts, ", "))
	}

	cfg.normalize()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks config consistency.
func (c Config) Validate() error {
	if strings.TrimSpace(c.App.LogLevel) == "" {
		return fmt.Errorf("app.log_level must not be empty")
	}

	if c.DNS.Enabled {
		if strings.TrimSpace(c.DNS.ConfigPath) == "" {
			return fmt.Errorf("dns.config_path must not be empty when dns.enabled=true")
		}
		if len(c.DNS.ReloadCommand) == 0 {
			return fmt.Errorf("dns.reload_command must not be empty when dns.enabled=true")
		}
	}

	if c.Firewall.Enabled {
		if strings.TrimSpace(c.Firewall.Family) == "" || strings.TrimSpace(c.Firewall.Table) == "" || strings.TrimSpace(c.Firewall.Chain) == "" || strings.TrimSpace(c.Firewall.SetName) == "" {
			return fmt.Errorf("firewall.family/table/chain/set_name must not be empty when firewall.enabled=true")
		}
		for _, ip := range c.Firewall.BlockedIPs {
			if net.ParseIP(ip) == nil {
				return fmt.Errorf("invalid IP in firewall.blocked_ips: %q", ip)
			}
		}
	}

	if strings.TrimSpace(c.Inspector.Mode) == "" {
		return fmt.Errorf("inspector.mode must not be empty")
	}

	return nil
}

func (c *Config) normalize() {
	c.App.LogLevel = strings.ToLower(strings.TrimSpace(c.App.LogLevel))
	if c.App.LogLevel == "" {
		c.App.LogLevel = "info"
	}

	if strings.TrimSpace(c.DNS.ConfigPath) == "" {
		c.DNS.ConfigPath = "/etc/dnsmasq.d/dpi.conf"
	}
	if len(c.DNS.ReloadCommand) == 0 {
		c.DNS.ReloadCommand = []string{"systemctl", "reload", "dnsmasq"}
	}
	c.DNS.BlockedDomains = normalizeStrings(c.DNS.BlockedDomains, true)

	if strings.TrimSpace(c.Firewall.Family) == "" {
		c.Firewall.Family = "inet"
	}
	if strings.TrimSpace(c.Firewall.Table) == "" {
		c.Firewall.Table = "dpi"
	}
	if strings.TrimSpace(c.Firewall.Chain) == "" {
		c.Firewall.Chain = "input"
	}
	if strings.TrimSpace(c.Firewall.SetName) == "" {
		c.Firewall.SetName = "blocked_ips"
	}
	c.Firewall.BlockedIPs = normalizeStrings(c.Firewall.BlockedIPs, false)

	c.Inspector.Mode = strings.TrimSpace(c.Inspector.Mode)
	if c.Inspector.Mode == "" {
		c.Inspector.Mode = "skeleton"
	}
}

func normalizeStrings(values []string, lower bool) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		candidate := strings.TrimSpace(value)
		if lower {
			candidate = strings.ToLower(candidate)
		}
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	return out
}

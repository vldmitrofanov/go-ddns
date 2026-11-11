package main

import (
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

const defaultConfigPath = "/etc/go-ddns/config.toml"

type Config struct {
	Listen string `toml:"listen"`
	Port   int    `toml:"port"`
	DBPath string `toml:"db_path"`

	// Only honour X-Forwarded-For / X-Real-IP when the TCP peer is one of these.
	TrustedProxies []string `toml:"trusted_proxies"`

	// Log Route 53 changes instead of sending them (for testing).
	DryRun bool `toml:"dry_run"`

	TLS       TLSConfig       `toml:"tls"`
	AWS       AWSConfig       `toml:"aws"`
	Blacklist BlacklistConfig `toml:"blacklist"`

	trustedProxies []netip.Prefix
}

type TLSConfig struct {
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
}

type AWSConfig struct {
	AccessKeyID     string `toml:"access_key_id"`
	SecretAccessKey string `toml:"secret_access_key"`
	Region          string `toml:"region"`
	DefaultTTL      int64  `toml:"default_ttl"`
}

type BlacklistConfig struct {
	Dir          string   `toml:"dir"`           // every *.txt / *.list / *.conf file in here is loaded
	AutoFile     string   `toml:"auto_file"`     // where automatic bans get appended
	MaxFailures  int      `toml:"max_failures"`  // failures before auto-ban
	Window       duration `toml:"window"`        // ...within this window
	Whitelist    []string `toml:"whitelist"`     // never ban these (IPs or CIDRs)
	PollInterval duration `toml:"poll_interval"` // how often to re-read changed files

	whitelist []netip.Prefix
}

type duration struct{ time.Duration }

func (d *duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	d.Duration = v
	return err
}

func loadConfig(path string) (*Config, error) {
	c := &Config{
		Listen: "0.0.0.0",
		Port:   8053,
		DBPath: "/var/lib/go-ddns/ddns.db",
		AWS:    AWSConfig{Region: "us-east-1", DefaultTTL: 60},
		Blacklist: BlacklistConfig{
			Dir:          "/etc/go-ddns/blacklist.d",
			AutoFile:     "/etc/go-ddns/blacklist.d/auto.txt",
			MaxFailures:  5,
			Window:       duration{10 * time.Minute},
			PollInterval: duration{10 * time.Second},
			Whitelist:    []string{"127.0.0.1/32", "::1/128"},
		},
	}
	if _, err := toml.DecodeFile(path, c); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	if c.Port <= 0 || c.Port > 65535 {
		return nil, fmt.Errorf("config: invalid port %d", c.Port)
	}
	var err error
	if c.trustedProxies, err = parsePrefixes(c.TrustedProxies); err != nil {
		return nil, fmt.Errorf("config trusted_proxies: %w", err)
	}
	if c.Blacklist.whitelist, err = parsePrefixes(c.Blacklist.Whitelist); err != nil {
		return nil, fmt.Errorf("config blacklist.whitelist: %w", err)
	}
	if c.Blacklist.MaxFailures <= 0 {
		c.Blacklist.MaxFailures = 5
	}
	if c.AWS.DefaultTTL <= 0 {
		c.AWS.DefaultTTL = 60
	}
	return c, nil
}

// parsePrefix accepts "1.2.3.4", "1.2.3.0/24", "2001:db8::1", "2001:db8::/32".
func parsePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("bad IP/CIDR %q", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func parsePrefixes(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		p, err := parsePrefix(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func inPrefixes(ip netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func configPathFromEnv() string {
	if p := os.Getenv("GO_DDNS_CONFIG"); p != "" {
		return p
	}
	return defaultConfigPath
}

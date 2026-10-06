package config

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
)

// ReadOnly decodes and validates configuration without creating credentials,
// assigning a new instance identity, or persisting migration/default values.
func ReadOnly(path string) (Config, error) {
	file, err := os.Open(path) // #nosec G304 -- local operator-selected diagnostic path.
	if err != nil {
		return Config{}, err
	}
	defer file.Close()
	const limit = 4 << 20
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return Config{}, err
	}
	if len(data) > limit {
		return Config{}, errors.New("diagnostic configuration exceeds 4 MiB")
	}
	cfg := Default()
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	if cfg.Version == 0 || cfg.Version == 1 {
		migrateV1(&cfg)
	}
	if cfg.Web.Port == 0 {
		cfg.Web.Port = 9080
	}
	if cfg.Web.ListenIPv4 == "" && cfg.Web.ListenIPv6 == "" {
		cfg.Web.ListenIPv4, cfg.Web.ListenIPv6 = "127.0.0.1", "::1"
	}
	cfg.Web.TLSCertFile = strings.TrimSpace(cfg.Web.TLSCertFile)
	cfg.Web.TLSKeyFile = strings.TrimSpace(cfg.Web.TLSKeyFile)
	cfg.Web.TLSMinVersion = strings.TrimSpace(cfg.Web.TLSMinVersion)
	cfg.Web.DNSServers, err = NormalizeDNSServers(cfg.Web.DNSServers)
	if err != nil {
		return Config{}, err
	}
	applyConfigDefaults(&cfg)
	return cfg, Validate(cfg)
}

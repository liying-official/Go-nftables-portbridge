package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNormalizeWhitelist(t *testing.T) {
	got, err := NormalizeWhitelist([]string{"192.168.1.9", "192.168.1.10/24", "2001:db8::1", " 192.168.1.9 "})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(got, ",")
	for _, want := range []string{"192.168.1.0/24", "192.168.1.9/32", "2001:db8::1/128"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %s in %v", want, got)
		}
	}
}

func TestDefaultWebPort(t *testing.T) {
	if got := Default().Web.Port; got != 9080 {
		t.Fatalf("default web port = %d, want 9080", got)
	}
}

func TestSecureManagementDefaults(t *testing.T) {
	cfg := Default()
	if cfg.Web.ListenIPv4 != "127.0.0.1" || cfg.Web.ListenIPv6 != "::1" || cfg.Web.AutoLANACL {
		t.Fatalf("unexpected management defaults: %+v", cfg.Web)
	}
	cfg.Web.ListenIPv4 = "0.0.0.0"
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "allow_insecure_http") {
		t.Fatalf("non-loopback plaintext listener error = %v", err)
	}
	cfg.Web.AllowInsecureHTTP = true
	if err := Validate(cfg); err != nil {
		t.Fatalf("explicit insecure compatibility mode rejected: %v", err)
	}
	cfg.Web.Whitelist = []string{"0.0.0.0/0"}
	if err := Validate(cfg); err == nil {
		t.Fatal("all-address management ACL was accepted without the unsafe override")
	}
	cfg.Web.AllowUnsafeAllACL = true
	absCert := filepath.Join(string(os.PathSeparator), "etc", "portbridge-tls", "fullchain.pem")
	absKey := filepath.Join(string(os.PathSeparator), "etc", "portbridge-tls", "privkey.pem")
	cfg.Web.TLSCertFile, cfg.Web.TLSKeyFile = absCert, absKey
	cfg.Web.StrictIPAllowlist = true
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "strict IP allowlist") {
		t.Fatalf("strict mode accepted /0 through unsafe compatibility flag: %v", err)
	}
}

func TestTargetAddressPolicy(t *testing.T) {
	rule := NormalizeRule(Rule{})
	private := netip.MustParseAddr("192.168.50.10")
	if err := ValidateTargetAddress(rule, private); err == nil {
		t.Fatal("private target was accepted by default")
	}
	rule.AllowPrivateTarget = true
	rule.TargetCIDRAllowlist = []string{"192.168.50.0/24"}
	if err := ValidateTargetAddress(rule, private); err != nil {
		t.Fatalf("explicitly allowed private target rejected: %v", err)
	}
	if err := ValidateTargetAddress(rule, netip.MustParseAddr("192.168.32.10")); err == nil {
		t.Fatal("private target outside the CIDR allowlist was accepted")
	}
	if err := ValidateTargetAddress(rule, netip.MustParseAddr("169.254.169.254")); err == nil {
		t.Fatal("cloud metadata target was accepted outside the CIDR allowlist")
	}
	if _, err := NormalizeTargetCIDRs([]string{"0.0.0.0/0"}); err == nil {
		t.Fatal("all-address target CIDR was accepted")
	}
}

func TestV1MigrationMakesLegacyRisksExplicit(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	tokenPath := filepath.Join(dir, "admin.token")
	legacy := `{
  "version": 1,
  "web": {"port":9080,"listen_ipv4":"0.0.0.0","listen_ipv6":"::","auto_lan_acl":true,"whitelist":[],"dns_servers":[],"admin_token_sha256":""},
  "rules": [{"id":"legacy","name":"legacy","protocol":"tcp","listen_host":"*","listen_port":10000,"target_host":"192.168.50.10","target_port":80,"enabled":true,"max_udp_sessions":65536,"udp_session_buffer_bytes":262144}]
}`
	if err := os.WriteFile(configPath, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	store, generated, err := LoadOrCreate(configPath, tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if generated == "" {
		t.Fatal("migration did not generate the missing token")
	}
	cfg := store.Get()
	if cfg.Version != CurrentVersion || !cfg.Web.AllowInsecureHTTP {
		t.Fatalf("legacy management risk was not made explicit: %+v", cfg.Web)
	}
	if len(cfg.Rules) != 1 || !cfg.Rules[0].AllowPrivateTarget || len(cfg.Rules[0].TargetCIDRAllowlist) == 0 {
		t.Fatalf("legacy private target exception was not migrated: %+v", cfg.Rules)
	}
	if err := ValidateTargetAddress(cfg.Rules[0], netip.IPv6Loopback()); err != nil {
		t.Fatalf("legacy IPv6 loopback compatibility was not migrated: %v", err)
	}
	if cfg.NFT.ConntrackMark != DefaultNFTConntrackMark || !cfg.NFT.EnableFlowtable {
		t.Fatalf("legacy nftables settings were not migrated: %+v", cfg.NFT)
	}
	if cfg.Rules[0].MaxUDPSessions != 4096 || cfg.Rules[0].UDPSessionBufferBytes != 64*1024 {
		t.Fatalf("legacy UDP defaults were not migrated to bounded defaults: %+v", cfg.Rules[0])
	}
}

func normalizeTestRule(rule Rule) Rule {
	if strings.HasPrefix(rule.TargetHost, "127.") {
		rule.AllowPrivateTarget = true
		rule.TargetCIDRAllowlist = []string{"127.0.0.0/8"}
	}
	return NormalizeRule(rule)
}

func TestStrictIPAllowlistValidation(t *testing.T) {
	absCert := filepath.Join(string(os.PathSeparator), "etc", "portbridge", "tls", "fullchain.pem")
	absKey := filepath.Join(string(os.PathSeparator), "etc", "portbridge", "tls", "privkey.pem")
	valid := Default()
	valid.Web.AutoLANACL = false
	valid.Web.StrictIPAllowlist = true
	valid.Web.Whitelist = []string{"192.0.2.10"}
	valid.Web.TLSCertFile = absCert
	valid.Web.TLSKeyFile = absKey
	if err := Validate(valid); err != nil {
		t.Fatalf("valid strict allowlist rejected: %v", err)
	}

	for name, mutate := range map[string]func(*Config){
		"automatic LAN ACL": func(c *Config) { c.Web.AutoLANACL = true },
		"empty whitelist":   func(c *Config) { c.Web.Whitelist = nil },
		"missing TLS key":   func(c *Config) { c.Web.TLSKeyFile = "" },
		"relative TLS path": func(c *Config) { c.Web.TLSCertFile = "tls.crt" },
		"all IPv4 addresses": func(c *Config) {
			c.Web.Whitelist = []string{"0.0.0.0/0"}
		},
		"all IPv6 addresses": func(c *Config) {
			c.Web.Whitelist = []string{"::/0"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := Validate(candidate); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestWhitelistEntryLimit(t *testing.T) {
	entries := make([]string, 0, MaxWhitelistEntries+1)
	for i := 0; i <= MaxWhitelistEntries; i++ {
		entries = append(entries, fmt.Sprintf("2001:db8::%x", i))
	}
	if _, err := NormalizeWhitelist(entries); err == nil {
		t.Fatalf("more than %d whitelist entries were accepted", MaxWhitelistEntries)
	}
}

func TestRuleDataPlaneNormalizationAndValidation(t *testing.T) {
	rule := NormalizeRule(Rule{})
	if rule.DataPlane != RuleDataPlaneNFT {
		t.Fatalf("default data plane = %q, want %q", rule.DataPlane, RuleDataPlaneNFT)
	}
	rule = NormalizeRule(Rule{DataPlane: " GO "})
	if rule.DataPlane != RuleDataPlaneGo {
		t.Fatalf("normalized data plane = %q", rule.DataPlane)
	}
	cfg := Default()
	cfg.Rules = []Rule{normalizeTestRule(Rule{
		ID: "invalid-plane", Name: "invalid-plane", Protocol: ProtocolTCP,
		DataPlane: "invalid", ListenHost: "127.0.0.1", ListenPort: 10000,
		TargetHost: "127.0.0.1", TargetPort: 10001, Enabled: true,
	})}
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "data plane") {
		t.Fatalf("invalid data plane error = %v", err)
	}
}

func TestUDPPerformanceDefaultsAndValidation(t *testing.T) {
	rule := NormalizeRule(Rule{})
	if rule.UDPWorkers != 0 || rule.UDPBatchSize != 64 || rule.UDPPacketBufferSize != 2048 {
		t.Fatalf("unexpected UDP defaults: workers=%d batch=%d packet=%d", rule.UDPWorkers, rule.UDPBatchSize, rule.UDPPacketBufferSize)
	}
	if rule.UDPListenerBufferBytes != 4*1024*1024 || rule.UDPSessionBufferBytes != 64*1024 {
		t.Fatalf("unexpected UDP socket buffers: listener=%d session=%d", rule.UDPListenerBufferBytes, rule.UDPSessionBufferBytes)
	}

	base := normalizeTestRule(Rule{
		ID: "udp-performance", Name: "udp-performance", Protocol: ProtocolUDP,
		DataPlane: RuleDataPlaneGo, ListenHost: "127.0.0.1", ListenPort: 10000,
		TargetHost: "127.0.0.1", TargetPort: 10001, Enabled: true,
	})
	for name, mutate := range map[string]func(*Rule){
		"workers":       func(r *Rule) { r.UDPWorkers = 129 },
		"batch":         func(r *Rule) { r.UDPBatchSize = 257 },
		"packet buffer": func(r *Rule) { r.UDPPacketBufferSize = 256 },
		"listener":      func(r *Rule) { r.UDPListenerBufferBytes = 1024 },
		"session":       func(r *Rule) { r.UDPSessionBufferBytes = 1024 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			cfg := Default()
			cfg.Rules = []Rule{candidate}
			if err := Validate(cfg); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestNormalizeDNSServers(t *testing.T) {
	got, err := NormalizeDNSServers([]string{"1.1.1.1", "8.8.8.8:5353", "2001:4860:4860::8888", " 1.1.1.1:53 "})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"1.1.1.1:53", "8.8.8.8:5353", "[2001:4860:4860::8888]:53"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("DNS servers = %v, want %v", got, want)
	}
	for _, invalid := range []string{"dns.example.com", "1.1.1.1:0", "1.1.1.1:65536"} {
		if _, err := NormalizeDNSServers([]string{invalid}); err == nil {
			t.Fatalf("invalid DNS server %q was accepted", invalid)
		}
	}
}

func TestRuleConflict(t *testing.T) {
	cfg := Default()
	cfg.Rules = []Rule{
		normalizeTestRule(Rule{ID: "a", Name: "a", Protocol: "tcp", ListenHost: "*", ListenPort: 9000, TargetHost: "127.0.0.1", TargetPort: 80, Enabled: true}),
		normalizeTestRule(Rule{ID: "b", Name: "b", Protocol: "tcp", ListenHost: "127.0.0.1", ListenPort: 9000, TargetHost: "127.0.0.1", TargetPort: 81, Enabled: true}),
	}
	if err := Validate(cfg); err == nil {
		t.Fatal("expected overlapping listen conflict")
	}
	cfg.Rules[1].Protocol = "udp"
	if err := Validate(cfg); err != nil {
		t.Fatalf("TCP and UDP should be allowed on the same port: %v", err)
	}
	cfg.Rules[1].Protocol = ProtocolBoth
	if err := Validate(cfg); err == nil {
		t.Fatal("TCP+UDP should conflict with TCP on the same address and port")
	}
	cfg.Rules[0].Protocol = ProtocolUDP
	if err := Validate(cfg); err == nil {
		t.Fatal("TCP+UDP should conflict with UDP on the same address and port")
	}
}

func TestValidateBothProtocol(t *testing.T) {
	cfg := Default()
	cfg.Rules = []Rule{
		normalizeTestRule(Rule{ID: "both", Name: "both", Protocol: ProtocolBoth, ListenHost: "127.0.0.1", ListenPort: 9000, TargetHost: "127.0.0.1", TargetPort: 9001, Enabled: true}),
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("TCP+UDP protocol should be valid: %v", err)
	}
}

func TestValidatePortRange(t *testing.T) {
	cfg := Default()
	cfg.Rules = []Rule{
		normalizeTestRule(Rule{
			ID: "range", Name: "range", Protocol: ProtocolTCP,
			ListenHost: "127.0.0.1", ListenPort: 10000, ListenPortEnd: 10009,
			TargetHost: "127.0.0.1", TargetPort: 20000, TargetPortEnd: 20009,
			Enabled: true,
		}),
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("valid port range rejected: %v", err)
	}
	cfg.Rules[0].TargetPortEnd = 20008
	if err := Validate(cfg); err == nil {
		t.Fatal("mismatched port range sizes should be rejected")
	}
	cfg.Rules[0].TargetPortEnd = 20009
	cfg.Rules[0].ListenPortEnd = 9999
	if err := Validate(cfg); err == nil {
		t.Fatal("descending listen range should be rejected")
	}
	cfg.Rules[0].ListenPort = 10000
	cfg.Rules[0].ListenPortEnd = 10000 + MaxPortRangeSize
	cfg.Rules[0].TargetPort = 20000
	cfg.Rules[0].TargetPortEnd = 20000 + MaxPortRangeSize
	if err := Validate(cfg); err == nil {
		t.Fatal("oversized port range should be rejected")
	}
}

func TestPortRangeConflict(t *testing.T) {
	cfg := Default()
	cfg.Rules = []Rule{
		normalizeTestRule(Rule{
			ID: "range-a", Name: "range-a", Protocol: ProtocolTCP,
			ListenHost: "127.0.0.1", ListenPort: 10000, ListenPortEnd: 10009,
			TargetHost: "127.0.0.1", TargetPort: 20000, TargetPortEnd: 20009,
			Enabled: true,
		}),
		normalizeTestRule(Rule{
			ID: "range-b", Name: "range-b", Protocol: ProtocolTCP,
			ListenHost: "127.0.0.1", ListenPort: 10009, ListenPortEnd: 10019,
			TargetHost: "127.0.0.1", TargetPort: 30000, TargetPortEnd: 30010,
			Enabled: true,
		}),
	}
	if err := Validate(cfg); err == nil {
		t.Fatal("overlapping port ranges should conflict")
	}
	cfg.Rules[1].ListenPort = 10010
	cfg.Rules[1].TargetPortEnd = 30009
	if err := Validate(cfg); err != nil {
		t.Fatalf("adjacent non-overlapping ranges should be valid: %v", err)
	}
	cfg.Rules[1].Protocol = ProtocolUDP
	cfg.Rules[1].ListenPort = 10009
	cfg.Rules[1].TargetPortEnd = 30010
	if err := Validate(cfg); err != nil {
		t.Fatalf("TCP and UDP ranges may overlap: %v", err)
	}
	cfg.Rules[1].Protocol = ProtocolBoth
	if err := Validate(cfg); err == nil {
		t.Fatal("TCP+UDP range should conflict with overlapping TCP range")
	}
}

func TestLoadOrCreateAndRotateToken(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	tokenPath := filepath.Join(dir, "admin.token")
	store, generated, err := LoadOrCreate(cfgPath, tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(generated) != 64 {
		t.Fatalf("unexpected token length: %d", len(generated))
	}
	if mark := store.Get().NFT.ConntrackMark; mark == 0 {
		t.Fatalf("fresh installation nftables mark = 0x%08x", mark)
	}
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != generated {
		t.Fatal("token file mismatch")
	}
	if info, err := os.Stat(tokenPath); err != nil {
		t.Fatal(err)
	} else if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("token mode = %o, want 600", got)
	}
	if info, err := os.Stat(cfgPath); err != nil {
		t.Fatal(err)
	} else if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("config mode = %o, want 600", got)
	}
	oldHash := store.Get().Web.AdminTokenSHA
	rotated, err := store.RotateAdminToken(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if rotated == generated || store.Get().Web.AdminTokenSHA == oldHash {
		t.Fatal("token was not rotated")
	}
}

func TestWriteSecretDoesNotFollowTemporarySymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation commonly requires elevated privileges on Windows")
	}
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	// This was the predictable temporary name used before atomic writes were
	// hardened. It must never be opened or followed.
	if err := os.Symlink(victim, filepath.Join(dir, "admin.token.tmp")); err != nil {
		t.Fatal(err)
	}
	if err := writeSecret(filepath.Join(dir, "admin.token"), "new-token\n"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "unchanged" {
		t.Fatalf("predictable temporary symlink was followed: %q", data)
	}
}

func TestCloneKeepsEmptyCollectionsNonNil(t *testing.T) {
	got := clone(Config{})
	if got.Web.Whitelist == nil {
		t.Fatal("empty whitelist became nil")
	}
	if got.Rules == nil {
		t.Fatal("empty rules became nil")
	}
}

func TestTLSMinVersionValidation(t *testing.T) {
	cfg := Default()
	for _, valid := range []string{"", TLSMinVersion12, TLSMinVersion13} {
		cfg.Web.TLSMinVersion = valid
		if err := Validate(cfg); err != nil {
			t.Fatalf("tls_min_version %q rejected: %v", valid, err)
		}
	}
	for _, invalid := range []string{"1.0", "1.1", "1.4", "tls1.3", "abc"} {
		cfg.Web.TLSMinVersion = invalid
		if err := Validate(cfg); err == nil {
			t.Fatalf("tls_min_version %q was accepted", invalid)
		}
	}
}

func TestLoadOrCreateTrimsTLSMinVersion(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfg := Default()
	cfg.Web.TLSMinVersion = " 1.3 "
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	store, _, err := LoadOrCreate(cfgPath, filepath.Join(dir, "admin.token"))
	if err != nil {
		t.Fatal(err)
	}
	if got := store.Get().Web.TLSMinVersion; got != TLSMinVersion13 {
		t.Fatalf("tls_min_version = %q, want %q", got, TLSMinVersion13)
	}
}

func TestTokenFileConsistency(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	tokenPath := filepath.Join(dir, "admin.token")
	store, generated, err := LoadOrCreate(cfgPath, tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(generated) != 64 {
		t.Fatalf("unexpected token length: %d", len(generated))
	}
	sha := store.Get().Web.AdminTokenSHA
	if !TokenFileConsistent(tokenPath, sha) {
		t.Fatal("fresh installation reports inconsistent token file")
	}
	// An interrupted rotation leaves a token the configuration no longer accepts.
	if err := os.WriteFile(tokenPath, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if TokenFileConsistent(tokenPath, sha) {
		t.Fatal("mismatched token file reported consistent")
	}
	if err := os.Remove(tokenPath); err != nil {
		t.Fatal(err)
	}
	if TokenFileConsistent(tokenPath, sha) {
		t.Fatal("missing token file reported consistent")
	}
	if !TokenFileConsistent("", sha) || !TokenFileConsistent(tokenPath, "") {
		t.Fatal("no-op inputs must be treated as consistent")
	}
	// A successful rotation restores file/configuration consistency.
	if _, err := store.RotateAdminToken(tokenPath); err != nil {
		t.Fatal(err)
	}
	if !TokenFileConsistent(tokenPath, store.Get().Web.AdminTokenSHA) {
		t.Fatal("rotated installation reports inconsistent token file")
	}
}

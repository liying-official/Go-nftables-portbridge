package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"portbridge/internal/config"
)

const (
	nftTableName     = "portbridge"
	nftFlowtableName = "fastpath"
	nftOwnerPrefix   = "Go-nftables-portbridge:managed:v1"
)

type nftRuleSpec struct {
	RuleID          string
	Family          int
	ListenHost      netip.Addr
	ListenPort      int
	ListenPortEnd   int
	TargetHost      netip.Addr
	TargetPort      int
	TargetPortEnd   int
	Protocol        string
	ConntrackMark   uint32
	EnableFlowtable bool
}

func (s nftRuleSpec) key() string {
	return fmt.Sprintf("%s|%d|%s|%d-%d|%s|%d-%d|%s|%08x|%t", s.RuleID, s.Family,
		s.ListenHost, s.ListenPort, s.ListenPortEnd, s.TargetHost,
		s.TargetPort, s.TargetPortEnd, s.Protocol, s.ConntrackMark, s.EnableFlowtable)
}

type nftBackend interface {
	Replace([]nftRuleSpec) error
	Delete() error
	TopologyKey() string
}

type commandNFTBackend struct {
	binary      string
	logger      *slog.Logger
	mu          sync.Mutex
	initialized bool
	devicesKey  string
	initErr     error
	ownerMarker string
}

func CleanupNFT(logger *slog.Logger, nftConfig ...config.NFTConfig) error {
	backend := newCommandNFTBackend(logger)
	if len(nftConfig) > 0 {
		backend.setConfig(nftConfig[0])
	}
	return backend.Delete()
}

func newCommandNFTBackend(logger *slog.Logger) *commandNFTBackend {
	var binary string
	for _, candidate := range []string{"/usr/sbin/nft", "/usr/bin/nft"} {
		if trustedRootExecutable(candidate) {
			binary = candidate
			break
		}
	}
	backend := &commandNFTBackend{binary: binary, logger: logger, ownerMarker: nftOwnerMarker(config.DefaultNFTConntrackMark)}
	if binary == "" {
		backend.initErr = errors.New("no trusted root-owned nft executable was found in the fixed system paths")
	}
	return backend
}

func (n *commandNFTBackend) setConfig(nftConfig config.NFTConfig) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.ownerMarker = nftOwnerMarker(nftConfig.ConntrackMark)
}

func nftOwnerMarker(mark uint32) string {
	return fmt.Sprintf("%s:%08x", nftOwnerPrefix, mark)
}

func trustedRootExecutable(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return false
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return false
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	return true
}

func (n *commandNFTBackend) Replace(specs []nftRuleSpec) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	exists, owned, err := n.tableState()
	if err != nil {
		return err
	}
	if exists && !owned {
		return fmt.Errorf("refusing to modify foreign nftables table inet %s without ownership marker %q", nftTableName, n.ownerMarker)
	}
	if len(specs) == 0 {
		if !exists {
			n.initialized = false
			n.devicesKey = ""
			return nil
		}
		if err := n.run("delete table inet "+nftTableName+"\n", "-f", "-"); err != nil {
			return err
		}
		n.initialized = false
		n.devicesKey = ""
		return nil
	}
	devices := []string{}
	if specsUseFlowtable(specs) {
		devices, err = nftFlowtableDevices()
		if err != nil {
			return fmt.Errorf("discover nftables flowtable devices: %w", err)
		}
		if len(devices) == 0 {
			return errors.New("no non-loopback device is available for the nftables flowtable")
		}
	}
	devicesKey := strings.Join(devices, "\x00")
	if exists && n.initialized && n.devicesKey == devicesKey {
		if err := n.run(renderNFTChainRefreshScript(specs), "-f", "-"); err == nil {
			return nil
		} else {
			n.logger.Warn("nftables chain refresh failed; rebuilding managed table", "error", err)
		}
	}
	if err := n.run(renderNFTScript(specs, exists, devices), "-f", "-"); err != nil {
		return err
	}
	n.initialized = true
	n.devicesKey = devicesKey
	return nil
}

func (n *commandNFTBackend) TopologyKey() string {
	if n.initErr != nil {
		return "error:" + n.initErr.Error()
	}
	devices, err := nftFlowtableDevices()
	if err != nil {
		return "error:" + err.Error()
	}
	return strings.Join(devices, "\x00")
}

func (n *commandNFTBackend) Delete() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	exists, owned, err := n.tableState()
	if err != nil {
		return err
	}
	if !exists {
		n.initialized = false
		n.devicesKey = ""
		return nil
	}
	if !owned {
		return fmt.Errorf("refusing to delete foreign nftables table inet %s without ownership marker %q", nftTableName, n.ownerMarker)
	}
	if err := n.run("delete table inet "+nftTableName+"\n", "-f", "-"); err != nil {
		return err
	}
	n.initialized = false
	n.devicesKey = ""
	return nil
}

func (n *commandNFTBackend) tableState() (bool, bool, error) {
	if n.initErr != nil {
		return false, false, n.initErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, n.binary, "list", "table", "inet", nftTableName) // #nosec G204 -- binary is selected from fixed, root-owned, non-writable system paths.
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	output, err := cmd.CombinedOutput()
	if err == nil {
		return true, strings.Contains(string(output), `comment "`+n.ownerMarker+`"`), nil
	}
	if errors.Is(err, exec.ErrNotFound) {
		return false, false, fmt.Errorf("nft executable not found at %s", n.binary)
	}
	message := string(output)
	if strings.Contains(message, "No such file or directory") || strings.Contains(message, "does not exist") {
		return false, false, nil
	}
	if ctx.Err() != nil {
		return false, false, fmt.Errorf("check nftables table: %w", ctx.Err())
	}
	return false, false, fmt.Errorf("check nftables table: %w: %s", err, strings.TrimSpace(message))
}

func (n *commandNFTBackend) run(input string, args ...string) error {
	if n.initErr != nil {
		return n.initErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, n.binary, args...) // #nosec G204 -- binary is trusted and all arguments are internal fixed nft options.
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	cmd.Stdin = strings.NewReader(input)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("apply nftables transaction: %w", ctx.Err())
		}
		return fmt.Errorf("apply nftables transaction: %w: %s", err, strings.TrimSpace(output.String()))
	}
	return nil
}

func nftSpecsKey(specs []nftRuleSpec) string {
	keys := make([]string, 0, len(specs))
	for _, spec := range specs {
		keys = append(keys, spec.key())
	}
	sort.Strings(keys)
	return strings.Join(keys, "\n")
}

func specsUseFlowtable(specs []nftRuleSpec) bool {
	for _, spec := range specs {
		if spec.EnableFlowtable {
			return true
		}
	}
	return false
}

func renderNFTScript(specs []nftRuleSpec, exists bool, devices []string) string {
	devices = append([]string(nil), devices...)
	sort.Strings(devices)

	var b strings.Builder
	if exists {
		b.WriteString("flush table inet " + nftTableName + "\n")
	} else {
		mark := config.DefaultNFTConntrackMark
		if len(specs) > 0 && specs[0].ConntrackMark != 0 {
			mark = specs[0].ConntrackMark
		}
		fmt.Fprintf(&b, "add table inet %s { comment %q; }\n", nftTableName, nftOwnerMarker(mark))
	}
	b.WriteString("add chain inet " + nftTableName + " prerouting { type nat hook prerouting priority dstnat; policy accept; }\n")
	b.WriteString("add chain inet " + nftTableName + " output { type nat hook output priority dstnat; policy accept; }\n")
	b.WriteString("add chain inet " + nftTableName + " postrouting { type nat hook postrouting priority srcnat; policy accept; }\n")
	if specsUseFlowtable(specs) {
		fmt.Fprintf(&b, "add flowtable inet %s %s { hook ingress priority filter; devices = { %s }; counter; }\n",
			nftTableName, nftFlowtableName, nftDeviceSet(devices))
	}
	b.WriteString("add chain inet " + nftTableName + " forward { type filter hook forward priority filter; policy accept; }\n")
	writeNFTRules(&b, specs)
	return b.String()
}

func renderNFTChainRefreshScript(specs []nftRuleSpec) string {
	var b strings.Builder
	for _, chain := range []string{"prerouting", "output", "postrouting", "forward"} {
		fmt.Fprintf(&b, "flush chain inet %s %s\n", nftTableName, chain)
	}
	writeNFTRules(&b, specs)
	return b.String()
}

func writeNFTRules(b *strings.Builder, specs []nftRuleSpec) {
	sorted := append([]nftRuleSpec(nil), specs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].key() < sorted[j].key() })
	for _, spec := range sorted {
		for _, hook := range []string{"prerouting", "output"} {
			fmt.Fprintf(b, "add rule inet %s %s %s %s dport %s ct mark set 0x%08x counter %s comment %q\n",
				nftTableName, hook, nftDestinationMatch(spec, hook), spec.Protocol,
				portText(spec.ListenPort, spec.ListenPortEnd), spec.ConntrackMark, nftDNAT(spec), nftComment(spec, hook))
		}
		fmt.Fprintf(b, "add rule inet %s postrouting ct mark 0x%08x %s %s dport %s counter masquerade comment %q\n",
			nftTableName, spec.ConntrackMark, nftTargetMatch(spec), spec.Protocol,
			portText(spec.TargetPort, spec.TargetPortEnd), nftComment(spec, "postrouting"))
		if spec.EnableFlowtable {
			fmt.Fprintf(b, "add rule inet %s forward ct mark 0x%08x %s %s dport %s ct state established,related flow add @%s counter accept comment %q\n",
				nftTableName, spec.ConntrackMark, nftTargetMatch(spec), spec.Protocol,
				portText(spec.TargetPort, spec.TargetPortEnd), nftFlowtableName, nftComment(spec, "flowtable"))
		} else {
			fmt.Fprintf(b, "add rule inet %s forward ct mark 0x%08x %s %s dport %s counter accept comment %q\n",
				nftTableName, spec.ConntrackMark, nftTargetMatch(spec), spec.Protocol,
				portText(spec.TargetPort, spec.TargetPortEnd), nftComment(spec, "forward"))
		}
	}
}

func nftFlowtableDevices() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	devices := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		devices = append(devices, iface.Name)
	}
	sort.Strings(devices)
	return devices, nil
}

func nftDeviceSet(devices []string) string {
	quoted := make([]string, 0, len(devices))
	for _, device := range devices {
		quoted = append(quoted, strconv.Quote(device))
	}
	return strings.Join(quoted, ", ")
}

func nftDestinationMatch(spec nftRuleSpec, hook string) string {
	family := "ipv6"
	addressExpr := "ip6 daddr " + spec.ListenHost.String()
	if spec.Family == 4 {
		family = "ipv4"
		addressExpr = "ip daddr " + spec.ListenHost.String()
	}
	if spec.ListenHost.IsUnspecified() {
		addressExpr = "fib daddr type local"
		if hook == "output" {
			if spec.Family == 4 {
				addressExpr = "ip daddr != 127.0.0.0/8 " + addressExpr
			} else {
				addressExpr = "ip6 daddr != ::1 " + addressExpr
			}
		}
	}
	return "meta nfproto " + family + " " + addressExpr
}

func nftTargetMatch(spec nftRuleSpec) string {
	if spec.Family == 4 {
		return "meta nfproto ipv4 ip daddr " + spec.TargetHost.String()
	}
	return "meta nfproto ipv6 ip6 daddr " + spec.TargetHost.String()
}

func nftDNAT(spec nftRuleSpec) string {
	family := "ip6"
	host := "[" + spec.TargetHost.String() + "]"
	if spec.Family == 4 {
		family = "ip"
		host = spec.TargetHost.String()
	}
	if spec.ListenPortEnd > spec.ListenPort {
		return "dnat " + family + " to " + host + " : " + nftPortMap(spec)
	}
	return "dnat " + family + " to " + host + ":" + portText(spec.TargetPort, spec.TargetPortEnd)
}

// nftPortMap preserves the configured one-to-one offset for a port range.
// A bare DNAT target range is a NAT allocation pool and may select any target
// port from the range, so it cannot implement listen N -> target N mapping.
func nftPortMap(spec nftRuleSpec) string {
	var b strings.Builder
	b.WriteString(spec.Protocol)
	b.WriteString(" dport map { ")
	for listenPort := spec.ListenPort; listenPort <= spec.ListenPortEnd; listenPort++ {
		if listenPort != spec.ListenPort {
			b.WriteString(", ")
		}
		b.WriteString(strconv.Itoa(listenPort))
		b.WriteString(" : ")
		b.WriteString(strconv.Itoa(spec.TargetPort + listenPort - spec.ListenPort))
	}
	b.WriteString(" }")
	return b.String()
}

func nftComment(spec nftRuleSpec, hook string) string {
	sum := sha256.Sum256([]byte(spec.RuleID))
	return fmt.Sprintf("pb:%x:%d:%s:%s", sum[:6], spec.Family, spec.Protocol, hook)
}

func portText(start, end int) string {
	if end == 0 || end == start {
		return strconv.Itoa(start)
	}
	return strconv.Itoa(start) + "-" + strconv.Itoa(end)
}

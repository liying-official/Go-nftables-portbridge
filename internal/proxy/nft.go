package proxy

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"portbridge/internal/config"
)

const (
	nftTableName     = "portbridge"
	nftFlowtableName = "fastpath"
	nftOwnerPrefix   = "Go-nftables-portbridge:managed:v1"
	// Admit acceleration after conventional forward-hook firewall decisions.
	// Equal-priority external chains are rejected because ordering is undefined.
	nftForwardPriority = 2147483647
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
	ruleIdentity    string // recovered full hash, or a tagged legacy short identity
}

type nftRenderState struct {
	retired       []nftRuleSpec
	suspended     []nftRuleSpec
	binding       string
	keepFlowtable bool
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
	logger           *slog.Logger
	mu               sync.Mutex
	initialized      bool
	devicesKey       string
	initErr          error
	ownerMarker      string
	kernel           nftKernelIO
	interfaces       func() ([]net.Interface, error)
	pendingTopology  nftTopologySnapshot
	topologyReady    bool
	fingerprint      string
	appliedSpecKey   string
	appliedActiveKey string
	conntrack        conntrackKernelIO
	activeSpecs      []nftRuleSpec
	pendingSpecs     []nftRuleSpec
	recovered        bool
	unknownState     bool
	suspendedSpecs   []nftRuleSpec
	policyFamilies   uint8
	store            *nftStateStore
	diskSession      *nftDiskSession
	diskBinding      string
	cleanProbe       func() error
	cleanVerified    bool
	configErr        error
}

func CleanupNFT(logger *slog.Logger, nftConfig ...config.NFTConfig) error {
	return CleanupNFTWithConfigPath(logger, "/etc/portbridge/config.json", nftConfig...)
}

// Cleanup and the running Manager must use the same actual config path/mark.
func CleanupNFTWithConfigPath(logger *slog.Logger, configPath string, nftConfig ...config.NFTConfig) error {
	backend := newCommandNFTBackend(logger)
	backend.store = newNFTStateStore(configPath)
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
	backend := &commandNFTBackend{logger: logger, ownerMarker: nftOwnerMarker(config.DefaultNFTConntrackMark)}
	if binary == "" {
		backend.initErr = errors.New("no trusted root-owned nft executable was found in the fixed system paths")
	}
	backend.kernel = &nftCommandIO{binary: binary, initErr: backend.initErr}
	backend.interfaces = net.Interfaces
	backend.conntrack = newCommandConntrack()
	backend.store = newNFTStateStore("/etc/portbridge/config.json")
	backend.cleanProbe = verifyEmptyNetfilter
	return backend
}

func (n *commandNFTBackend) setConfig(nftConfig config.NFTConfig) {
	n.mu.Lock()
	defer n.mu.Unlock()
	owner := nftOwnerMarker(nftConfig.ConntrackMark)
	if owner != n.ownerMarker && (n.recovered || len(n.activeSpecs)+len(n.pendingSpecs)+len(n.suspendedSpecs) > 0) {
		n.configErr = errors.New("instance mark change requires verified cleanup using the previous config/mark before restart")
		return
	}
	n.ownerMarker = owner
	n.configErr = nil
}

func nftOwnerMarker(mark uint32) string {
	return fmt.Sprintf("%s:%08x", nftOwnerPrefix, mark)
}

func trustedRootExecutable(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o111 == 0 {
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

func (n *commandNFTBackend) replaceObjects(specs, retired []nftRuleSpec, keepFlowtable bool, held ...[]nftRuleSpec) error {
	var suspended []nftRuleSpec
	if len(held) > 0 {
		suspended = held[0]
	}
	state, err := n.observe()
	if err != nil {
		return err
	}
	if state.exists && !state.owned {
		return fmt.Errorf("refusing to modify foreign nftables table inet %s without ownership marker %q", nftTableName, n.ownerMarker)
	}
	for _, spec := range uniqueNFTSpecs(specs, retired, suspended) {
		if spec.ConntrackMark == 0 || nftOwnerMarker(spec.ConntrackMark) != n.ownerMarker {
			return errors.New("nftables plan has a mismatched instance mark")
		}
		if err := validateRetirementSpec(spec); err != nil {
			return err
		}
	}
	topology := n.topologyForFlowtable(specsUseFlowtable(specs) || keepFlowtable)
	n.topologyReady = false
	if topology.err != nil {
		return fmt.Errorf("discover nftables flowtable devices: %w", topology.err)
	}
	if (specsUseFlowtable(specs) || keepFlowtable) && len(topology.devices) == 0 {
		return errors.New("no non-loopback device is available for the nftables flowtable")
	}
	devicesKey := topology.key()
	journal, err := decodeNFTJournal(state.objects, n.ownerMarker)
	if err != nil {
		return err
	}
	canRefresh := state.exists && n.initialized && n.devicesKey == devicesKey && state.fingerprint == n.fingerprint && journal.binding == n.diskBinding
	keyFor := func(active, retired, suspended []nftRuleSpec) string {
		return nftAppliedStateKey(active, retired, suspended, keepFlowtable, n.diskBinding)
	}
	specKey := keyFor(specs, retired, suspended)
	if canRefresh && specKey == n.appliedSpecKey {
		return nil
	}
	if !state.exists && len(specs)+len(retired)+len(suspended) == 0 && n.diskSession == nil {
		n.clearAppliedState()
		return nil
	}
	var persistErr error
	if n.diskSession != nil {
		confirmed := diskNFTSnapshot(n.activeSpecs, n.pendingSpecs, n.suspendedSpecs)
		target := diskNFTSnapshot(specs, retired, suspended)
		persistErr = n.diskSession.prepare(confirmed, target)
		if persistErr != nil {
			// A failed intent must not prevent independently justified withdrawal.
			// No new admissions or new offload; keep ALL old pending ownership.
			specs = previouslyAdmittedNFT(specs, n.activeSpecs)
			retired = uniqueNFTSpecs(n.pendingSpecs, retired, retiredNFTSpecs(n.activeSpecs, specs))
			suspended = gateNFTReplacements(suspended, retired)
			keepFlowtable = specsUseFlowtable(specs)
			topology = n.topologyForFlowtable(keepFlowtable)
			n.topologyReady = false
			if topology.err != nil {
				return errors.Join(persistErr, topology.err)
			}
			devicesKey = topology.key()
			canRefresh = canRefresh && n.devicesKey == devicesKey
			specKey = keyFor(specs, retired, suspended)
			if len(n.activeSpecs)+len(n.pendingSpecs)+len(n.suspendedSpecs) == 0 {
				return fmt.Errorf("persist recovery intent (new admission refused): %w", persistErr)
			}
		}
	}
	if len(specs)+len(retired)+len(suspended) == 0 {
		if state.exists {
			if _, err := n.kernel.Apply("delete table inet " + nftTableName + "\n"); err != nil {
				return errors.Join(persistErr, err)
			}
			observed, err := n.observe()
			if err != nil {
				n.initialized = false
				return errors.Join(persistErr, err)
			}
			if observed.exists {
				n.initialized = false
				return errors.New("owned nftables table deletion was not confirmed")
			}
		}
		n.clearAppliedState()
		if persistErr != nil {
			return persistErr
		}
		if n.diskSession != nil {
			if err := n.diskSession.checkpoint(diskNFTSnapshot(nil, nil, nil)); err != nil {
				return fmt.Errorf("persist empty recovery checkpoint: %w", err)
			}
		}
		return nil
	}
	renderState := nftRenderState{retired: retired, suspended: suspended, binding: n.diskBinding, keepFlowtable: keepFlowtable}
	options := nftJournalOptions{suspended: suspended, binding: n.diskBinding}
	activeKey := nftSpecsKey(specs)
	script := renderNFTScript(specs, state.exists, topology.names(), renderState)
	if canRefresh {
		if n.appliedActiveKey == activeKey {
			var b strings.Builder
			writeNFTJournal(&b, specs, retired, false, options)
			script = b.String()
		} else {
			script = renderNFTChainRefreshWithState(specs, [][]nftRuleSpec{retired}, options)
		}
	}
	if n.logger != nil {
		n.logger.Debug("applying managed nftables transaction", "rebuild_objects", !canRefresh, "paths", len(specs), "suspended_paths", len(suspended))
	}
	if _, err := n.kernel.Apply(script); err != nil {
		return errors.Join(persistErr, err)
	}
	observed, err := n.observe()
	if err != nil {
		n.initialized = false
		return errors.Join(persistErr, err)
	}
	if !observed.exists || !observed.owned {
		n.initialized = false
		return errors.New("managed nftables table changed before verification")
	}
	if err := validateNFTState(observed.objects, specs, topology.names(), n.ownerMarker, renderState); err != nil {
		n.initialized = false
		return errors.Join(persistErr, err)
	}
	n.initialized = true
	n.devicesKey = devicesKey
	n.fingerprint = observed.fingerprint
	n.appliedSpecKey = specKey
	n.appliedActiveKey = activeKey
	n.activeSpecs = append([]nftRuleSpec(nil), specs...)
	n.pendingSpecs = append([]nftRuleSpec(nil), retired...)
	n.suspendedSpecs = append([]nftRuleSpec(nil), suspended...)
	if persistErr != nil {
		return fmt.Errorf("old admission gated but recovery intent persistence failed: %w", persistErr)
	}
	if n.diskSession != nil {
		if err := n.diskSession.checkpoint(diskNFTSnapshot(specs, retired, suspended)); err != nil {
			n.initialized = false
			return fmt.Errorf("kernel readback succeeded but recovery checkpoint failed: %w", err)
		}
	}
	return nil
}

func (n *commandNFTBackend) TopologyKey() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.initErr != nil {
		return "error:" + n.initErr.Error()
	}
	list := n.interfaces
	if list == nil {
		list = net.Interfaces
	}
	n.pendingTopology = collectNFTTopology(list)
	n.topologyReady = true
	return n.pendingTopology.key()
}

func (n *commandNFTBackend) clearAppliedState() {
	n.initialized = false
	n.devicesKey = ""
	n.fingerprint = ""
	n.appliedSpecKey = ""
	n.appliedActiveKey = ""
	n.activeSpecs = nil
	n.pendingSpecs = nil
	n.suspendedSpecs = nil
	n.topologyReady = false
}

func (n *commandNFTBackend) topologyFor(specs []nftRuleSpec) nftTopologySnapshot {
	return n.topologyForFlowtable(specsUseFlowtable(specs))
}

func (n *commandNFTBackend) topologyForFlowtable(enabled bool) nftTopologySnapshot {
	if !enabled {
		return nftTopologySnapshot{}
	}
	if !n.topologyReady {
		list := n.interfaces
		if list == nil {
			list = net.Interfaces
		}
		n.pendingTopology = collectNFTTopology(list)
		n.topologyReady = true
	}
	return n.pendingTopology
}

func (n *commandNFTBackend) Healthy(specs []nftRuleSpec) (bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.refreshMissingExecutables()
	if n.configErr != nil {
		return false, n.configErr
	}
	if n.initErr != nil && len(specs) == 0 {
		if !n.cleanVerified {
			return false, nil
		}
		if err := n.verifyCLIIndependentEmpty(); err != nil {
			return false, err
		}
		return true, nil
	}
	n.cleanVerified = false
	state, err := n.observe()
	if err != nil {
		n.unknownState = true
		return false, err
	}
	if state.exists && !state.owned {
		n.unknownState = true
		return false, errors.New("managed nftables table owner does not match")
	}
	if specsUseFlowtable(specs) {
		if err := n.checkAdmissionFor(specs); err != nil {
			var admission *nftAdmissionError
			if !errors.As(err, &admission) {
				n.unknownState = true
			}
			return false, err
		}
	}
	if !n.recovered || len(n.pendingSpecs) > 0 || len(n.suspendedSpecs) > 0 || n.unknownState {
		return false, nil
	}
	if len(specs) == 0 {
		n.topologyReady = false
		return !state.exists, nil
	}
	topology := n.topologyFor(specs)
	if topology.err != nil {
		return false, topology.err
	}
	healthy := state.exists && n.initialized && n.appliedActiveKey == nftSpecsKey(specs) && n.devicesKey == topology.key() && n.fingerprint == state.fingerprint
	if healthy {
		n.topologyReady = false
	}
	return healthy, nil
}

func (n *commandNFTBackend) refreshMissingExecutables() {
	if command, ok := n.kernel.(*nftCommandIO); ok && command.initErr != nil {
		for _, path := range []string{"/usr/sbin/nft", "/usr/bin/nft"} {
			if trustedRootExecutable(path) {
				command.binary = path
				command.initErr = nil
				n.initErr = nil
				n.recovered = false
				n.cleanVerified = false
				break
			}
		}
	}
	if command, ok := n.conntrack.(*commandConntrack); ok && command.initErr != nil {
		n.conntrack = newCommandConntrack()
	}
}
func (n *commandNFTBackend) verifyCLIIndependentEmpty() error {
	n.cleanVerified = false
	if n.cleanProbe == nil {
		return n.initErr
	}
	if n.store != nil {
		if err := n.store.checkExisting(n.ownerMarker); err != nil {
			n.unknownState = true
			return err
		}
	}
	if err := n.cleanProbe(); err != nil {
		n.unknownState = true
		n.recovered = false
		return err
	}
	// Independent kernel evidence, not the lack of a CLI/file/current NFT plan.
	n.clearAppliedState()
	n.recovered = true
	n.unknownState = false
	n.cleanVerified = true
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

func renderNFTScript(specs []nftRuleSpec, exists bool, devices []string, journal ...nftRenderState) string {
	devices = append([]string(nil), devices...)
	sort.Strings(devices)

	var b strings.Builder
	var state nftRenderState
	if len(journal) > 0 {
		state = journal[0]
	}
	if exists {
		b.WriteString("delete table inet " + nftTableName + "\n")
	}
	mark := config.DefaultNFTConntrackMark
	if len(specs) > 0 && specs[0].ConntrackMark != 0 {
		mark = specs[0].ConntrackMark
	} else if len(state.retired) > 0 {
		mark = state.retired[0].ConntrackMark
	} else if len(state.suspended) > 0 {
		mark = state.suspended[0].ConntrackMark
	}
	fmt.Fprintf(&b, "add table inet %s { comment %q; }\n", nftTableName, nftOwnerMarker(mark))
	b.WriteString("add chain inet " + nftTableName + " prerouting { type nat hook prerouting priority dstnat; policy accept; }\n")
	b.WriteString("add chain inet " + nftTableName + " output { type nat hook output priority dstnat; policy accept; }\n")
	b.WriteString("add chain inet " + nftTableName + " postrouting { type nat hook postrouting priority srcnat; policy accept; }\n")
	if specsUseFlowtable(specs) || state.keepFlowtable {
		fmt.Fprintf(&b, "add flowtable inet %s %s { hook ingress priority filter; devices = { %s }; counter; }\n",
			nftTableName, nftFlowtableName, nftDeviceSet(devices))
	}
	fmt.Fprintf(&b, "add chain inet %s forward { type filter hook forward priority %d; policy accept; }\n", nftTableName, nftForwardPriority)
	writeNFTRules(&b, specs)
	if len(specs)+len(state.retired)+len(state.suspended) > 0 {
		writeNFTJournal(&b, specs, state.retired, true, nftJournalOptions{suspended: state.suspended, binding: state.binding})
	}
	return b.String()
}

func renderNFTChainRefreshScript(specs []nftRuleSpec, retired ...[]nftRuleSpec) string {
	return renderNFTChainRefreshWithState(specs, retired, nftJournalOptions{})
}
func renderNFTChainRefreshWithState(specs []nftRuleSpec, retired [][]nftRuleSpec, options nftJournalOptions) string {
	var b strings.Builder
	var pending []nftRuleSpec
	if len(retired) > 0 {
		pending = retired[0]
	}
	for _, chain := range []string{"prerouting", "output", "postrouting", "forward"} {
		fmt.Fprintf(&b, "flush chain inet %s %s\n", nftTableName, chain)
	}
	writeNFTRules(&b, specs)
	if len(specs)+len(pending)+len(options.suspended) > 0 {
		writeNFTJournal(&b, specs, pending, false, options)
	}
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
			fmt.Fprintf(b, "add rule inet %s forward ct mark 0x%08x %s %s dport %s %s ct state established,related flow add @%s counter accept comment %q\n",
				nftTableName, spec.ConntrackMark, nftTargetMatch(spec), spec.Protocol,
				portText(spec.TargetPort, spec.TargetPortEnd), nftOriginalFlowMatch(spec), nftFlowtableName, nftComment(spec, "flowtable"))
		} else {
			fmt.Fprintf(b, "add rule inet %s forward ct mark 0x%08x %s %s dport %s counter accept comment %q\n",
				nftTableName, spec.ConntrackMark, nftTargetMatch(spec), spec.Protocol,
				portText(spec.TargetPort, spec.TargetPortEnd), nftComment(spec, "forward"))
		}
	}
}

func nftDeviceSet(devices []string) string {
	quoted := make([]string, 0, len(devices))
	for _, device := range devices {
		quoted = append(quoted, strconv.Quote(device))
	}
	return strings.Join(quoted, ", ")
}

// Shared target/mark is not enough: a suspended rule must not borrow another
// rule's acceleration entry point for an existing NAT connection.
func nftOriginalFlowMatch(spec nftRuleSpec) string {
	text := "ct original proto-dst " + portText(spec.ListenPort, spec.ListenPortEnd)
	if !spec.ListenHost.IsUnspecified() {
		family := "ip"
		if spec.Family == 6 {
			family = "ip6"
		}
		text += " ct original " + family + " daddr " + spec.ListenHost.String()
	}
	return text
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

func nftAppliedStateKey(active, retired, suspended []nftRuleSpec, keepFlowtable bool, binding string) string {
	return nftSpecsKey(active) + "\nretired:" + nftSpecsKey(retired) + "\nsuspended:" + nftSpecsKey(suspended) + "\nkeep-flowtable:" + strconv.FormatBool(keepFlowtable) + "\nbinding:" + binding
}

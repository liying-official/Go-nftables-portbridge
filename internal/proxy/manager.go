package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"

	"portbridge/internal/config"
)

type Manager struct {
	mu             sync.Mutex
	logger         *slog.Logger
	runners        map[string]*runner
	stats          map[string]*Stats
	budgets        map[string]*ruleBudget
	resources      *resourceBudget
	rules          map[string]config.Rule
	desiredRules   map[string]config.Rule
	nftTombstones  map[string]string
	dataPlanes     map[string]string
	resolver       *DNSResolver
	resolved       map[string]resolvedTarget
	nft            nftBackend
	nftKey         string
	nftInitialized bool
	nftMark        uint32
	nftFlowtable   bool
	telemetry      *trafficCollector
}

type RuleRuntime struct {
	Rule        config.Rule     `json:"rule"`
	Stats       StatsSnapshot   `json:"stats"`
	DataPlane   string          `json:"data_plane"`
	GoRunning   bool            `json:"go_running"`
	KernelState string          `json:"kernel_state"`
	Traffic     TrafficSnapshot `json:"traffic"`
}

func NewManager(logger *slog.Logger, dnsServers ...[]string) *Manager {
	servers := []string{}
	if len(dnsServers) > 0 {
		servers = dnsServers[0]
	}
	return newManagerWithNFT(logger, NewDNSResolver(servers), newCommandNFTBackend(logger))
}

func newManagerWithNFT(logger *slog.Logger, resolver *DNSResolver, nft nftBackend) *Manager {
	defaults := config.Default()
	return &Manager{
		logger:        logger,
		runners:       make(map[string]*runner),
		stats:         make(map[string]*Stats),
		budgets:       make(map[string]*ruleBudget),
		resources:     newResourceBudget(defaults.Limits),
		rules:         make(map[string]config.Rule),
		desiredRules:  make(map[string]config.Rule),
		nftTombstones: make(map[string]string),
		dataPlanes:    make(map[string]string),
		resolver:      resolver,
		resolved:      make(map[string]resolvedTarget),
		nft:           nft,
		nftMark:       defaults.NFT.ConntrackMark,
		nftFlowtable:  defaults.NFT.EnableFlowtable,
		telemetry:     newTrafficCollector(),
	}
}

// SetNFTStateConfigPath is called before Apply, with the same config path that
// CleanupNFTWithConfigPath receives. Changing a live identity is not supported.
func (m *Manager) SetNFTStateConfigPath(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.rules) > 0 || m.nftInitialized {
		return fmt.Errorf("cannot change recovery location on an active manager")
	}
	if n, ok := m.nft.(*commandNFTBackend); ok {
		n.mu.Lock()
		defer n.mu.Unlock()
		n.store = newNFTStateStore(path)
	}
	return nil
}

func (m *Manager) SetRuntimeConfig(limits config.ResourceLimits, nftConfig config.NFTConfig) {
	m.mu.Lock()
	m.resources.setLimits(limits)
	if backend, ok := m.nft.(*commandNFTBackend); ok {
		backend.setConfig(nftConfig)
	}
	if m.nftMark != nftConfig.ConntrackMark || m.nftFlowtable != nftConfig.EnableFlowtable {
		m.nftInitialized = false
		m.nftKey = ""
	}
	m.nftMark = nftConfig.ConntrackMark
	m.nftFlowtable = nftConfig.EnableFlowtable
	m.mu.Unlock()
}

func (m *Manager) SetDNSServers(servers []string) {
	m.mu.Lock()
	m.resolver.SetServers(servers)
	m.resolved = make(map[string]resolvedTarget)
	rules := make([]config.Rule, 0, len(m.desiredRules))
	for _, rule := range m.desiredRules {
		rules = append(rules, rule)
	}
	m.mu.Unlock()
	m.Apply(rules)
}

func (m *Manager) Apply(rules []config.Rule) {
	m.apply(rules, false)
}

func (m *Manager) Refresh(rules []config.Rule) {
	m.apply(rules, true)
}

func (m *Manager) apply(rules []config.Rule, allowCachedDNS bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	desired := make(map[string]config.Rule, len(rules))
	for _, raw := range rules {
		r := config.NormalizeRule(raw)
		desired[r.ID] = r
		delete(m.nftTombstones, r.ID)
		if _, ok := m.stats[r.ID]; !ok {
			m.stats[r.ID] = &Stats{}
		}
		if _, ok := m.budgets[r.ID]; !ok {
			m.budgets[r.ID] = &ruleBudget{}
		}
	}
	m.desiredRules = desired
	plan := m.buildPlan(rules, allowCachedDNS)
	goErrors := make(map[string][]string)
	desiredSlots := make(map[string]goPath, len(plan.goRules))
	for pathKey, path := range plan.goRules {
		desiredSlots[goPathSlotKey(pathKey)] = path
	}

	for pathKey, current := range m.runners {
		path, exists := plan.goRules[pathKey]
		if !exists {
			// A DNS refresh can change only the target portion of a path key. Stop
			// the old listener before starting its replacement, otherwise the new
			// runner cannot bind and the rule remains down until the next refresh.
			path, exists = desiredSlots[goPathSlotKey(pathKey)]
		}
		if !exists || ruleKey(path.Rule) != ruleKey(current.rule) {
			current.stop()
			delete(m.runners, pathKey)
		}
	}

	newNFTKey := nftSpecsKey(plan.nftSpecs)
	if specsUseFlowtable(plan.nftSpecs) {
		newNFTKey += "\nflowtable-devices:" + m.nft.TopologyKey()
	}
	var nftErr error
	nftCleanupFailed := false
	nftInspectionFailed := false
	needsNFTUpdate := !m.nftInitialized || newNFTKey != m.nftKey
	if checker, ok := m.nft.(interface {
		Healthy([]nftRuleSpec) (bool, error)
	}); ok {
		healthy, healthErr := checker.Healthy(plan.nftSpecs)
		if healthErr != nil {
			var admission *nftAdmissionError
			if errors.As(healthErr, &admission) {
				needsNFTUpdate = true
			} else {
				nftErr = fmt.Errorf("inspect nftables state: %w", healthErr)
				nftCleanupFailed = true
				nftInspectionFailed = true
			}
		} else if !healthy {
			needsNFTUpdate = true
		}
	}
	if nftErr == nil && needsNFTUpdate {
		nftErr = m.nft.Replace(plan.nftSpecs)
		if nftErr == nil {
			m.nftInitialized = true
			m.nftKey = newNFTKey
			m.logger.Info("nftables data plane applied", "paths", len(plan.nftSpecs))
		} else {
			applyErr := nftErr
			if _, aware := m.nft.(nftRetirementReporter); aware {
				m.nftInitialized = false
				m.nftKey = ""
				m.logger.Error("nftables reconciliation incomplete; recovery state retained", "error", applyErr)
			} else if cleanupErr := m.nft.Delete(); cleanupErr == nil {
				m.nftInitialized = false
				m.nftKey = ""
				m.logger.Error("failed to apply nftables data plane; removed managed rules, old conntrack revocation is not established", "error", applyErr)
			} else {
				nftCleanupFailed = true
				nftErr = fmt.Errorf("%w; failed to remove possibly stale nftables rules: %v", applyErr, cleanupErr)
				m.logger.Error("failed to apply or clean up nftables data plane; stale forwarding may remain active", "error", nftErr)
			}
		}
	}

	blockedRules, verifiedNFT := m.nftRetirementStatus(desired, plan, nftErr, nftInspectionFailed)
	if _, aware := m.nft.(nftRetirementReporter); aware {
		nftCleanupFailed = false
	} else if nftCleanupFailed {
		for id, plane := range m.dataPlanes {
			if dataPlaneUsesNFT(plane) {
				blockedRules[id] = true
			}
		}
	}

	blockedGoPaths := make(map[string]bool)
	for pathKey, path := range plan.goRules {
		if _, aware := m.nft.(nftRetirementReporter); aware {
			blockedGoPaths[pathKey] = m.goPathBlockedByNFT(path.Rule, nftErr, nftInspectionFailed)
		} else {
			blockedGoPaths[pathKey] = blockedRules[path.RuleID]
		}
	}
	for pathKey, current := range m.runners {
		if blockedGoPaths[pathKey] {
			current.stop()
			delete(m.runners, pathKey)
		}
	}
	for pathKey, path := range plan.goRules {
		if _, ok := m.runners[pathKey]; ok {
			continue
		}
		if blockedGoPaths[pathKey] {
			goErrors[path.RuleID] = append(goErrors[path.RuleID], "waiting for previous kernel forwarding to be revoked")
			continue
		}
		r := path.Rule
		run := newRunner(r, m.stats[path.RuleID], m.logger, m.resolver)
		run.resources = m.resources
		run.budget = m.budgets[path.RuleID]
		if err := run.start(); err != nil {
			goErrors[path.RuleID] = append(goErrors[path.RuleID], err.Error())
			m.logger.Error("failed to start forwarding rule", "rule", r.Name, "id", path.RuleID, "path", pathKey, "error", err)
			continue
		}
		m.runners[pathKey] = run
		logGoPathStarted(m.logger, path)
	}

	for pathKey, current := range m.runners {
		if _, keep := plan.goRules[pathKey]; keep {
			continue
		}
		// A path that is no longer desired must stop even when the replacement
		// nftables transaction fails. Keeping stale forwarding favors availability
		// over the administrator's explicit disable/change request.
		current.stop()
		delete(m.runners, pathKey)
	}

	for id, r := range desired {
		previousPlane := m.dataPlanes[id]
		m.rules[id] = r
		m.dataPlanes[id] = plan.dataPlanes[id]
		if blockedRules[id] {
			// A newly requested Go path must not masquerade as a running NFT
			// rule merely because inspection is unavailable. The additive
			// kernel_state still explicitly exposes the unresolved risk.
			kernelState, known := m.nftRuleState(id)
			if !known && !dataPlaneUsesNFT(previousPlane) && plan.usesGo[id] {
				m.stats[id].setRunning(false, "Go listener is not running; kernel state is "+kernelState+": "+nftErr.Error())
				continue
			}
			if dataPlaneUsesNFT(previousPlane) {
				m.dataPlanes[id] = previousPlane
			} else {
				m.dataPlanes[id] = DataPlaneNFT
			}
			for _, run := range m.runners {
				if run.rule.ID == id {
					m.dataPlanes[id] = DataPlaneHybrid
					break
				}
			}
			if kernelState == "admission-suspended" {
				m.stats[id].setRunning(true, "new NFT admission is suspended; established NAT connections may remain; no automatic fallback: "+nftErr.Error())
			} else {
				m.stats[id].setRunning(true, "previous kernel forwarding may still be active; revocation is incomplete: "+nftErr.Error())
			}
			continue
		}
		if !r.Enabled {
			if nftCleanupFailed && dataPlaneUsesNFT(previousPlane) {
				m.dataPlanes[id] = previousPlane
				m.stats[id].setRunning(true, "failed to disable previous nftables path; forwarding may still be active: "+nftErr.Error())
				continue
			}
			m.stats[id].setRunning(false, "")
			continue
		}
		var failures []string
		if err := plan.errors[id]; err != nil {
			failures = append(failures, err.Error())
		}
		if plan.usesNFT[id] && nftErr != nil && !verifiedNFT[id] {
			failures = append(failures, nftErr.Error())
		}
		if errs := goErrors[id]; len(errs) > 0 {
			failures = append(failures, errs...)
		}
		for pathKey, path := range plan.goRules {
			if path.RuleID != id {
				continue
			}
			if _, running := m.runners[pathKey]; !running && len(goErrors[id]) == 0 {
				failures = append(failures, "Go proxy path is not running")
			}
		}
		hasPath := plan.usesNFT[id]
		if plan.usesGo[id] {
			hasPath = true
		}
		if len(failures) > 0 || !hasPath {
			if len(failures) == 0 {
				failures = append(failures, "no forwarding path could be created")
			}
			m.stats[id].setRunning(false, strings.Join(failures, "; "))
			continue
		}
		m.stats[id].setRunning(true, "")
	}

	for id := range m.rules {
		if _, ok := desired[id]; !ok {
			if blockedRules[id] {
				m.stats[id].setRunning(true, "previous kernel forwarding may still be active; revocation is incomplete: "+nftErr.Error())
				continue
			}
			if nftCleanupFailed && dataPlaneUsesNFT(m.dataPlanes[id]) {
				m.stats[id].setRunning(true, "failed to remove previous nftables path; forwarding may still be active: "+nftErr.Error())
				continue
			}
			delete(m.rules, id)
			delete(m.stats, id)
			delete(m.budgets, id)
			delete(m.dataPlanes, id)
			delete(m.resolved, id)
			delete(m.nftTombstones, id)
		}
	}
}

func dataPlaneUsesNFT(dataPlane string) bool {
	return dataPlane == DataPlaneNFT || dataPlane == DataPlaneHybrid
}

func logGoPathStarted(logger *slog.Logger, path goPath) {
	r := path.Rule
	logger.Info("Go proxy path started", "rule_id", path.RuleID, "protocol", r.Protocol)
	logger.Debug("Go proxy path endpoints", "rule_id", path.RuleID, "listen", ruleEndpointText(r.ListenHost, r.ListenPort, r.LastListenPort()), "target", ruleEndpointText(r.TargetHost, r.TargetPort, r.LastTargetPort()))
}

func (m *Manager) Stop() {
	if m.telemetry != nil {
		m.telemetry.stop()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, r := range m.runners {
		r.stop()
		delete(m.runners, id)
	}
	if err := m.nft.Delete(); err != nil {
		m.logger.Error("failed to remove nftables data plane", "error", err)
		for id, stats := range m.stats {
			if dataPlaneUsesNFT(m.dataPlanes[id]) {
				stats.setRunning(true, "kernel cleanup failed; previous forwarding may still be active: "+err.Error())
			} else {
				stats.setRunning(false, "")
			}
		}
	} else {
		for id, stats := range m.stats {
			stats.setRunning(false, "")
			m.dataPlanes[id] = DataPlaneDisabled
		}
	}
	m.nftInitialized = false
	m.nftKey = ""
}

func (m *Manager) Runtime() []RuleRuntime {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]RuleRuntime, 0, len(m.rules))
	for id, r := range m.rules {
		kernelState, _ := m.nftRuleState(id)
		goRunning := false
		for _, run := range m.runners {
			if run.rule.ID == id {
				goRunning = true
				break
			}
		}
		traffic := TrafficSnapshot{}
		if m.telemetry != nil {
			traffic = m.telemetry.snapshot(id, m.stats[id])
		}
		out = append(out, RuleRuntime{Rule: r, Stats: m.stats[id].snapshot(), DataPlane: m.dataPlanes[id], GoRunning: goRunning, KernelState: kernelState, Traffic: traffic})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Rule.Name == out[j].Rule.Name {
			return out[i].Rule.ID < out[j].Rule.ID
		}
		return out[i].Rule.Name < out[j].Rule.Name
	})
	return out
}

func ruleKey(r config.Rule) string {
	b, _ := json.Marshal(r)
	return string(b)
}

func goPathSlotKey(pathKey string) string {
	if index := strings.LastIndexByte(pathKey, '|'); index >= 0 {
		return pathKey[:index]
	}
	return pathKey
}

type runner struct {
	rule      config.Rule
	stats     *Stats
	logger    *slog.Logger
	resolver  *DNSResolver
	resources *resourceBudget
	budget    *ruleBudget
	ctx       context.Context
	cancel    context.CancelFunc

	mu      sync.Mutex
	closers []func()
	wg      sync.WaitGroup
}

func newRunner(rule config.Rule, stats *Stats, logger *slog.Logger, resolvers ...*DNSResolver) *runner {
	ctx, cancel := context.WithCancel(context.Background())
	resolver := NewDNSResolver(nil)
	if len(resolvers) > 0 && resolvers[0] != nil {
		resolver = resolvers[0]
	}
	defaults := config.Default()
	return &runner{
		rule: rule, stats: stats, logger: logger, resolver: resolver,
		resources: newResourceBudget(defaults.Limits), budget: &ruleBudget{},
		ctx: ctx, cancel: cancel,
	}
}

func (r *runner) start() error {
	protocols := []string{r.rule.Protocol}
	if r.rule.Protocol == config.ProtocolBoth {
		protocols = []string{config.ProtocolTCP, config.ProtocolUDP}
	}
	udpEndpoints := 0
	if r.rule.Protocol == config.ProtocolUDP || r.rule.Protocol == config.ProtocolBoth {
		for listenPort := r.rule.ListenPort; listenPort <= r.rule.LastListenPort(); listenPort++ {
			endpoints, err := listenEndpoints(r.rule.ListenHost, listenPort, config.ProtocolUDP)
			if err != nil {
				return err
			}
			udpEndpoints += len(endpoints)
		}
	}
	udpWorkerPlan := distributeUDPWorkers(effectiveUDPWorkers(r.rule.UDPWorkers), udpEndpoints)
	totalUDPWorkers := 0
	for _, workers := range udpWorkerPlan {
		totalUDPWorkers += workers
	}
	udpEndpointIndex := 0
	for listenPort := r.rule.ListenPort; listenPort <= r.rule.LastListenPort(); listenPort++ {
		targetPort := r.rule.TargetPort + listenPort - r.rule.ListenPort
		for _, protocol := range protocols {
			endpoints, err := listenEndpoints(r.rule.ListenHost, listenPort, protocol)
			if err != nil {
				r.stop()
				return err
			}
			for _, ep := range endpoints {
				if protocol == config.ProtocolTCP {
					if err := r.startTCP(ep, targetPort); err != nil {
						r.stop()
						return err
					}
				} else {
					workerCount := udpWorkerPlan[udpEndpointIndex]
					udpEndpointIndex++
					if err := r.startUDP(ep, targetPort, workerCount, totalUDPWorkers); err != nil {
						r.stop()
						return err
					}
				}
			}
		}
	}
	return nil
}

func distributeUDPWorkers(workerBudget, endpoints int) []int {
	if endpoints <= 0 {
		return nil
	}
	if workerBudget < endpoints {
		workerBudget = endpoints
	}
	plan := make([]int, endpoints)
	remainingWorkers := workerBudget
	for i := range plan {
		remainingEndpoints := endpoints - i
		workers := remainingWorkers / remainingEndpoints
		if remainingWorkers%remainingEndpoints != 0 {
			workers++
		}
		plan[i] = workers
		remainingWorkers -= workers
	}
	return plan
}

func (r *runner) addCloser(fn func()) {
	r.mu.Lock()
	r.closers = append(r.closers, fn)
	r.mu.Unlock()
}

func (r *runner) stop() {
	r.cancel()
	r.mu.Lock()
	closers := append([]func(){}, r.closers...)
	r.closers = nil
	r.mu.Unlock()
	for _, closeFn := range closers {
		closeFn()
	}
	r.wg.Wait()
}

type listenEndpoint struct {
	network string
	address string
}

func listenEndpoints(host string, port int, proto string) ([]listenEndpoint, error) {
	portText := fmt.Sprintf("%d", port)
	if host == "*" {
		return []listenEndpoint{
			{network: proto + "4", address: "0.0.0.0:" + portText},
			{network: proto + "6", address: "[::]:" + portText},
		}, nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, err
	}
	family := "6"
	if ip.Is4() {
		family = "4"
	}
	return []listenEndpoint{{network: proto + family, address: endpointText(host, port)}}, nil
}

func endpointText(host string, port int) string {
	if host == "*" {
		return "*:" + strconv.Itoa(port)
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func ruleEndpointText(host string, start, end int) string {
	if start == end {
		return endpointText(host, start)
	}
	hostText := host
	if host == "*" {
		hostText = "*"
	} else if strings.Contains(host, ":") {
		hostText = "[" + host + "]"
	}
	return hostText + ":" + strconv.Itoa(start) + "-" + strconv.Itoa(end)
}

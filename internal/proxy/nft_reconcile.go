package proxy

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type nftRetirementState struct {
	Active    []nftRuleSpec
	Pending   []nftRuleSpec
	Suspended []nftRuleSpec
	Verified  bool
	Unknown   bool
}

func (n *commandNFTBackend) retirementState() nftRetirementState {
	n.mu.Lock()
	defer n.mu.Unlock()
	return nftRetirementState{Active: append([]nftRuleSpec(nil), n.activeSpecs...), Pending: append([]nftRuleSpec(nil), n.pendingSpecs...), Suspended: append([]nftRuleSpec(nil), n.suspendedSpecs...), Verified: n.initialized || n.cleanVerified, Unknown: n.unknownState || !n.recovered}
}
func (n *commandNFTBackend) recoverKernelState(desired []nftRuleSpec) error {
	state, err := n.observe()
	if err != nil {
		return err
	}
	if state.exists && !state.owned {
		return errors.New("refusing to recover a foreign nftables table")
	}
	if n.recovered && n.initialized && state.exists && state.fingerprint == n.fingerprint {
		// The file was locked and validated by begin. Do not dump conntrack or
		// rewrite a checkpoint on an unchanged refresh, including policy suspension.
		if n.diskSession == nil {
			return nil
		}
		if n.diskSession.record != nil && n.diskBinding == "pb-disk:v1:"+n.diskSession.context.ConfigSHA256+":"+n.diskSession.record.Instance {
			return nil
		}
	}
	known := append(append(append([]nftRuleSpec(nil), desired...), n.activeSpecs...), n.suspendedSpecs...)
	active, pending, suspended := uniqueNFTSpecs(n.activeSpecs), uniqueNFTSpecs(n.pendingSpecs), uniqueNFTSpecs(n.suspendedSpecs)
	if n.diskSession != nil && n.diskSession.record != nil {
		// An intent is NOT evidence of installation. Only the previous confirmed
		// ownership scope is imported from disk. Actual owned kernel records below
		// supply any install that crashed before its confirmation reached disk.
		a, p, s := n.diskSession.record.Confirmed.specs()
		active = uniqueNFTSpecs(active, a)
		pending = uniqueNFTSpecs(pending, p)
		suspended = uniqueNFTSpecs(suspended, s)
		known = append(append(append(known, a...), p...), s...)
	}
	var journal nftJournalState
	if state.exists {
		journal, err = decodeNFTJournal(state.objects, n.ownerMarker)
		if err != nil {
			return err
		}
		legacy, err := recoverLegacyNFTSpecs(state.objects, n.ownerMarker)
		if err != nil {
			return err
		}
		known = append(known, journal.active...)
		active = uniqueNFTSpecs(active, resolveNFTIdentities(journal.active, known), resolveNFTIdentities(legacy, known))
		pending = uniqueNFTSpecs(pending, resolveNFTIdentities(journal.retired, known))
		suspended = uniqueNFTSpecs(suspended, resolveNFTIdentities(journal.suspended, known))
	}
	if n.diskSession != nil {
		n.diskBinding, err = n.diskSession.binding(journal.binding)
		if err != nil {
			return err
		}
	} else if journal.binding != "" {
		return errors.New("bound kernel journal requires its recovery store")
	}
	active = resolveNFTIdentities(active, known)
	pending = resolveNFTIdentities(pending, known)
	suspended = resolveNFTIdentities(suspended, known)
	if len(active)+len(pending)+len(suspended) > maxNFTRetiredSpecs {
		return errors.New("recoverable nftables state exceeds limit")
	}
	if err := n.conntrack.Available(); err != nil {
		if len(active)+len(pending)+len(suspended) == 0 {
			// CLI absence alone is not absence of orphaned NAT. A restricted kernel
			// read may independently prove an entirely empty inventory.
			if n.cleanProbe == nil {
				return err
			}
			if probeErr := n.cleanProbe(); probeErr != nil {
				return errors.Join(err, probeErr)
			}
		} else {
			n.activeSpecs, n.pendingSpecs, n.suspendedSpecs = active, pending, suspended
			n.recovered = true
			n.unknownState = true
			n.initialized = false
			return nil // the caller can still gate attributable old admission
		}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		mark, err := n.configuredMark()
		if err != nil {
			cancel()
			return err
		}
		entries, err := n.conntrack.ListOwned(ctx, mark)
		cancel()
		if err != nil {
			return err
		}
		history := uniqueNFTSpecs(active, pending, suspended)
		for _, entry := range entries {
			matched := false
			for _, spec := range history {
				if conntrackMatchesSpec(entry, spec) {
					matched = true
					break
				}
			}
			if !matched {
				return errors.New("unattributable marked conntrack state: restore verified ownership records before cleanup")
			}
		}
	}
	n.activeSpecs, n.pendingSpecs, n.suspendedSpecs = active, pending, suspended
	n.recovered = true
	n.unknownState = false
	n.initialized = false
	// A normal restart adopts only a fully re-read, owner-verified object set
	// agreeing with a durable checkpoint. An unconfirmed intent is never a
	// fast path: it must finish the ordinary durable reconciliation first.
	durable := n.diskSession == nil
	if n.diskSession != nil && n.diskSession.record != nil {
		record := n.diskSession.record
		durable = record.Phase == "checkpoint" && sameNFTDiskSnapshot(record.Confirmed, diskNFTSnapshot(active, pending, suspended))
	}
	if state.exists && durable {
		flow := false
		for _, object := range state.objects {
			if _, ok := object["flowtable"]; ok {
				flow = true
			}
		}
		topology := n.topologyForFlowtable(flow)
		n.topologyReady = false
		expected := nftRenderState{retired: pending, suspended: suspended, binding: n.diskBinding, keepFlowtable: flow}
		if topology.err == nil && validateNFTState(state.objects, active, topology.names(), n.ownerMarker, expected) == nil {
			n.initialized = true
			n.fingerprint = state.fingerprint
			n.devicesKey = topology.key()
			n.appliedActiveKey = nftSpecsKey(active)
			n.appliedSpecKey = nftAppliedStateKey(active, pending, suspended, flow, n.diskBinding)
			for _, spec := range suspended {
				if spec.Family == 4 {
					n.policyFamilies |= 1
				} else if spec.Family == 6 {
					n.policyFamilies |= 2
				}
			}
		}
	}
	return nil
}

// Retain only already admitted paths. No new tuple or newly enabled offload is
// allowed when the revocation/persistence dependency is unavailable.
func previouslyAdmittedNFT(desired, active []nftRuleSpec) []nftRuleSpec {
	var kept []nftRuleSpec
	for _, next := range desired {
		var candidates []nftRuleSpec
		for _, old := range active {
			if !next.EnableFlowtable || old.EnableFlowtable {
				candidates = append(candidates, old)
			}
		}
		missing := retiredNFTSpecs([]nftRuleSpec{next}, candidates)
		kept = append(kept, gateNFTReplacements([]nftRuleSpec{next}, missing)...)
	}
	return uniqueNFTSpecs(kept)
}

func (n *commandNFTBackend) Replace(specs []nftRuleSpec) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.conntrack == nil {
		n.conntrack = newCommandConntrack()
	}
	n.refreshMissingExecutables()
	if n.configErr != nil && len(specs) > 0 {
		return n.configErr
	}
	if n.initErr != nil && len(specs) == 0 {
		return n.verifyCLIIndependentEmpty()
	}
	n.cleanVerified = false
	if n.store != nil {
		session, err := n.store.begin(n.ownerMarker, n.verifyNewBootScope)
		if err != nil {
			n.initialized = false
			n.unknownState = true
			return fmt.Errorf("open independent nft recovery state: %w", err)
		}
		n.diskSession = session
		if session.rolledBoot {
			// The independent proof excluded CURRENT related state. Old process
			// caches, like old disk snapshots, are not current ownership evidence.
			n.clearAppliedState()
			n.recovered = false
			n.unknownState = false
			n.diskBinding = ""
			n.policyFamilies = 0
		}
		defer func() { session.close(); n.diskSession = nil }()
	}
	if err := n.recoverKernelState(specs); err != nil {
		n.initialized = false
		n.unknownState = true
		return fmt.Errorf("recover previous nftables state: %w", err)
	}

	// Compute the administrator's retirement difference BEFORE any safety gate.
	// In particular a global policy rejection must never turn desired into nil
	// and accidentally revoke every unrelated connection by the shared mark.
	history := uniqueNFTSpecs(n.activeSpecs, n.suspendedSpecs)
	pending := uniqueNFTSpecs(n.pendingSpecs, retiredNFTSpecs(history, specs))
	if len(pending) > maxNFTRetiredSpecs {
		n.pendingSpecs = pending
		return errors.New("pending nftables retirement exceeds the bounded journal")
	}
	next := append([]nftRuleSpec(nil), specs...)
	var suspended []nftRuleSpec
	var admission *nftAdmissionError
	if specsUseFlowtable(specs) {
		if err := n.checkAdmissionFor(specs); err != nil {
			if !errors.As(err, &admission) {
				return err
			}
			next = nil
			for _, spec := range specs {
				if !admission.affects(spec) {
					next = append(next, spec)
				}
			}
			retained := gateNFTReplacements(history, retiredNFTSpecs(history, specs))
			for _, spec := range retained {
				if admission.affects(spec) {
					suspended = append(suspended, spec)
				}
			}
			// Remove affected cached acceleration as well as new admission. Rebuild
			// only on an increased rejection scope; never delete B's conntrack.
			if admission.families & ^n.policyFamilies != 0 {
				n.initialized = false
			}
			// A new rejection within an already gated family must also evict
			// cached acceleration. Compare still-desired ACTIVE scopes, not merely
			// the family mask, and do not retire unrelated conntrack entries.
			for _, active := range gateNFTReplacements(n.activeSpecs, retiredNFTSpecs(n.activeSpecs, specs)) {
				if admission.affects(active) {
					n.initialized = false
					break
				}
			}
		}
	}
	dependencyErr := n.conntrack.Available()
	if dependencyErr != nil {
		next = previouslyAdmittedNFT(next, n.activeSpecs)
		if len(history)+len(pending) == 0 {
			return dependencyErr
		}
	}
	n.pendingSpecs = pending
	keepFlowtable := specsUseFlowtable(next)
	if len(pending) > 0 {
		gated := gateNFTReplacements(next, pending)
		if err := n.replaceObjects(gated, pending, keepFlowtable, suspended); err != nil {
			return fmt.Errorf("stage nftables retirement: %w", err)
		}
		if admission != nil {
			n.policyFamilies = admission.families
		} else {
			n.policyFamilies = 0
		}
		if err := revokeNFTConnections(n.conntrack, pending); err != nil {
			return fmt.Errorf("previous nftables connections may still be active: %w", err)
		}
	}
	if err := n.replaceObjects(next, nil, keepFlowtable, suspended); err != nil {
		return err
	}
	n.pendingSpecs = nil
	n.unknownState = dependencyErr != nil
	if admission != nil {
		n.policyFamilies = admission.families
	} else {
		n.policyFamilies = 0
	}
	if admission != nil {
		return errors.Join(admission, dependencyErr)
	}
	return dependencyErr
}
func (n *commandNFTBackend) Delete() error { return n.Replace(nil) }

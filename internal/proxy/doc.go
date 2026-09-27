// Package proxy plans TCP/UDP forwarding and coordinates Go runners with owned
// nftables state. Configured intent and observed forwarding state are separate:
// an accepted configuration does not prove successful forwarding or retirement.
//
// # Rule lifecycle
//
// plan.go resolves and authorizes targets, then selects Go and/or nft paths.
// Manager.apply holds the manager lock while stopChangedRunners removes obsolete
// listeners, decideNFTAction/reconcileNFT check and apply kernel state, and
// reconcileRunners gates overlapping Go paths on retirement evidence. It then
// updates runtime status. The ordering is important:
// a failed replacement must not leave an obsolete listener forwarding traffic.
//
// nft.go declares backend capabilities and renders the owned table. Reconciliation
// and readback live in nft_reconcile.go and nft_state.go; external-policy proofs
// are bounded by the hook/accept/selective-ACL helpers. Admission and exact
// conntrack retirement are distinct operations, not one atomic transaction.
//
// nft_journal.go and nft_recovery.go track owned paths in the kernel, while
// nft_disk_linux.go protects same-identity recovery records. The manager's
// manager_nft_state.go projects pending/unknown state and retains cleanup rows.
// Missing ownership is never permission to guess conntrack deletion; an nft
// failure does not by itself authorize a Go fallback or imply that old flows stop.
//
// # Nft source map
//
// Reconciliation/readback: nft.go, nft_reconcile.go, nft_state.go, and
// nft_inspect_rules.go. Recovery/retirement: nft_journal.go, nft_recovery.go,
// nft_disk_linux.go, nft_boot_scope_linux.go, and nft_clean_linux.go. External
// policy probes: nft_empty_hooks_linux.go, nft_transparent_accept_linux.go,
// and nft_selective_acl_linux.go. Observation: nft_telemetry.go. These remain
// one package so reconciliation and recovery share the same ownership model.
//
// # Data plane and observation
//
// tcp.go and udp.go own Go forwarding and share logical-rule resource budgets.
// Those budgets do not automatically constrain the nftables path. telemetry.go
// samples outside packet handling, and nft_telemetry.go performs bounded,
// best-effort kernel reads. Status consumers read snapshots; collecting metrics
// does not grant admission, retire flows, or change forwarding decisions.
package proxy

package proxy

import (
	"net"
	"sync/atomic"
	"time"
)

// BackendConnectivity reports only a TCP connect probe, never application
// health. UDP sends are intentionally not treated as a health signal.
type BackendConnectivity struct {
	CheckType string    `json:"check_type"`
	Status    string    `json:"status"`
	CheckedAt time.Time `json:"checked_at,omitempty"`
}

type tcpTargetState struct {
	primaryReachable atomic.Bool
	backupReachable  atomic.Bool
	checkedUnixNano  atomic.Int64
}

func (r *runner) startTCPHealth(state *tcpTargetState, primary, backup string) {
	interval := time.Duration(r.rule.TCPHealthIntervalSeconds) * time.Second
	timeout := time.Duration(r.rule.TCPHealthTimeoutSeconds) * time.Second
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if r.ctx.Err() != nil {
				return
			}
			state.primaryReachable.Store(probeTCPConnect(r, primary, timeout))
			if backup != "" {
				state.backupReachable.Store(probeTCPConnect(r, backup, timeout))
			}
			if r.ctx.Err() == nil {
				state.checkedUnixNano.Store(time.Now().UnixNano())
			}
			select {
			case <-r.ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func probeTCPConnect(r *runner, address string, timeout time.Duration) bool {
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(r.ctx, "tcp", address)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (r *runner) backendConnectivity() BackendConnectivity {
	result := BackendConnectivity{CheckType: "tcp_connect", Status: "not_checked"}
	for _, state := range r.healthStates {
		checked := state.checkedUnixNano.Load()
		next := BackendConnectivity{CheckType: "tcp_connect", Status: "warming_up"}
		if checked > 0 {
			next.CheckedAt = time.Unix(0, checked)
			next.Status = "unreachable"
			if state.backupReachable.Load() {
				next.Status = "backup_reachable"
			}
			if state.primaryReachable.Load() {
				next.Status = "primary_reachable"
			}
		}
		result = mergeBackendConnectivity(result, next)
	}
	return result
}

func mergeBackendConnectivity(a, b BackendConnectivity) BackendConnectivity {
	priority := map[string]int{"not_checked": 0, "primary_reachable": 1, "backup_reachable": 2, "warming_up": 3, "unreachable": 4}
	if priority[b.Status] > priority[a.Status] {
		a.Status = b.Status
	}
	if b.CheckedAt.After(a.CheckedAt) {
		a.CheckedAt = b.CheckedAt
	}
	return a
}

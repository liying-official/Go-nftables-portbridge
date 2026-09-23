package proxy

import (
	"sync"
	"sync/atomic"
	"time"
)

type Stats struct {
	activeTCP   atomic.Int64
	activeUDP   atomic.Int64
	totalTCP    atomic.Uint64
	totalUDP    atomic.Uint64
	tcpRejected atomic.Uint64
	bytesUp     atomic.Uint64
	bytesDown   atomic.Uint64
	udpUp       atomic.Uint64
	udpDown     atomic.Uint64
	udpDrops    atomic.Uint64

	mu        sync.RWMutex
	running   bool
	startedAt time.Time
	lastError string
	liveTCP   map[*tcpMeter]struct{}
}

type StatsSnapshot struct {
	Running           bool      `json:"running"`
	StartedAt         time.Time `json:"started_at,omitempty"`
	LastError         string    `json:"last_error,omitempty"`
	ActiveTCP         int64     `json:"active_tcp"`
	ActiveUDPSessions int64     `json:"active_udp_sessions"`
	TotalTCP          uint64    `json:"total_tcp"`
	TotalUDPSessions  uint64    `json:"total_udp_sessions"`
	TCPRejected       uint64    `json:"tcp_rejected"`
	BytesUp           uint64    `json:"bytes_up"`
	BytesDown         uint64    `json:"bytes_down"`
	UDPPacketsUp      uint64    `json:"udp_packets_up"`
	UDPPacketsDown    uint64    `json:"udp_packets_down"`
	UDPDrops          uint64    `json:"udp_drops"`
}

func (s *Stats) setRunning(v bool, err string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	wasRunning := s.running
	s.running = v
	s.lastError = err
	if v && !wasRunning {
		s.startedAt = time.Now()
	}
}

func (s *Stats) snapshot() StatsSnapshot {
	s.mu.RLock()
	running, started, lastErr := s.running, s.startedAt, s.lastError
	s.mu.RUnlock()
	return StatsSnapshot{
		Running:           running,
		StartedAt:         started,
		LastError:         lastErr,
		ActiveTCP:         s.activeTCP.Load(),
		ActiveUDPSessions: s.activeUDP.Load(),
		TotalTCP:          s.totalTCP.Load(),
		TotalUDPSessions:  s.totalUDP.Load(),
		TCPRejected:       s.tcpRejected.Load(),
		BytesUp:           s.bytesUp.Load(),
		BytesDown:         s.bytesDown.Load(),
		UDPPacketsUp:      s.udpUp.Load(),
		UDPPacketsDown:    s.udpDown.Load(),
		UDPDrops:          s.udpDrops.Load(),
	}
}

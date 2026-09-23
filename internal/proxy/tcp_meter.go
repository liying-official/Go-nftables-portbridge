package proxy

import (
	"net"
	"sync/atomic"
)

// Sampling TCP_INFO keeps the io.Copy/splice path unwrapped. Completed copies
// replace live estimates under the same lock, rather than being counted twice.
type tcpMeter struct {
	client, upstream                   net.Conn
	upBase, downBase, upLast, downLast uint64
	upDone, downDone                   atomic.Int64
}

func (s *Stats) beginTCPMeter(client, upstream net.Conn) *tcpMeter {
	up, okUp := tcpBytesAcknowledged(upstream)
	down, okDown := tcpBytesAcknowledged(client)
	if !okUp || !okDown {
		return nil
	}
	meter := &tcpMeter{client: client, upstream: upstream, upBase: up, downBase: down}
	meter.upDone.Store(-1)
	meter.downDone.Store(-1)
	s.mu.Lock()
	if s.liveTCP == nil {
		s.liveTCP = make(map[*tcpMeter]struct{})
	}
	s.liveTCP[meter] = struct{}{}
	s.mu.Unlock()
	return meter
}

func meterDirection(conn net.Conn, base, last uint64, done *atomic.Int64) uint64 {
	if n := done.Load(); n >= 0 {
		return uint64(n)
	}
	n, ok := tcpBytesAcknowledged(conn)
	// Check again after reading TCP_INFO: EOF/CloseWrite may have added FIN.
	if final := done.Load(); final >= 0 {
		return uint64(final)
	}
	if ok && n >= base && n-base > last {
		return n - base
	}
	return last
}

func (s *Stats) trafficBytes() (uint64, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	up, down := s.bytesUp.Load(), s.bytesDown.Load()
	for m := range s.liveTCP {
		m.upLast = meterDirection(m.upstream, m.upBase, m.upLast, &m.upDone)
		m.downLast = meterDirection(m.client, m.downBase, m.downLast, &m.downDone)
		up += m.upLast
		down += m.downLast
	}
	return up, down
}

//go:build linux

package proxy

import (
	"context"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// monitorTCPIdle reads Linux TCP_INFO counters periodically. It preserves the
// *net.TCPConn values used by io.Copy/ReadFrom, so Linux splice remains
// available while idle connections are still reclaimed.
func monitorTCPIdle(ctx context.Context, timeout time.Duration, connections ...net.Conn) func() {
	if timeout <= 0 {
		return func() {}
	}
	interval := timeout / 4
	if interval < time.Second {
		interval = time.Second
	}
	if interval > 5*time.Second {
		interval = 5 * time.Second
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		lastChange := time.Now()
		previous, _ := tcpActivitySignature(connections)
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case now := <-ticker.C:
				current, ok := tcpActivitySignature(connections)
				if !ok || current != previous {
					previous = current
					lastChange = now
					continue
				}
				if now.Sub(lastChange) >= timeout {
					for _, connection := range connections {
						_ = connection.Close()
					}
					return
				}
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() { close(stop) })
		<-done
	}
}

func tcpActivitySignature(connections []net.Conn) (uint64, bool) {
	var signature uint64
	for _, connection := range connections {
		tcp, ok := connection.(*net.TCPConn)
		if !ok {
			return 0, false
		}
		raw, err := tcp.SyscallConn()
		if err != nil {
			return 0, false
		}
		var info *unix.TCPInfo
		var controlErr error
		if err := raw.Control(func(fd uintptr) {
			info, controlErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		}); err != nil || controlErr != nil || info == nil {
			return 0, false
		}
		signature += info.Bytes_acked + info.Bytes_received
	}
	return signature, true
}

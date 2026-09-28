package proxy

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

const tcpCopyBufferSize = 64 * 1024

var tcpCopyBufferPool = sync.Pool{
	New: func() any {
		buffer := make([]byte, tcpCopyBufferSize)
		return &buffer
	},
}

type readerFrom interface {
	ReadFrom(io.Reader) (int64, error)
}

func (r *runner) startTCP(ep listenEndpoint, targetPort int) error {
	listener, err := listenTCP(r.ctx, ep.network, ep.address)
	if err != nil {
		return err
	}
	var active sync.Map
	target := net.JoinHostPort(r.rule.TargetHost, strconv.Itoa(targetPort))
	backup := ""
	if r.rule.BackupTargetHost != "" {
		backupPort := r.rule.BackupTargetPort + targetPort - r.rule.TargetPort
		backup = net.JoinHostPort(r.rule.BackupTargetHost, strconv.Itoa(backupPort))
	}
	var health *tcpTargetState
	if r.rule.TCPHealthIntervalSeconds > 0 {
		health = &tcpTargetState{}
		r.healthStates = append(r.healthStates, health)
		r.startTCPHealth(health, target, backup)
	}
	dialer := &net.Dialer{
		Timeout:   time.Duration(r.rule.ConnectTimeoutSeconds) * time.Second,
		KeepAlive: 30 * time.Second,
	}
	r.addCloser(func() {
		_ = listener.Close()
		active.Range(func(key, _ any) bool {
			_ = key.(net.Conn).Close()
			return true
		})
	})

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		for {
			client, err := listener.Accept()
			if err != nil {
				if r.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
					r.logger.Warn("TCP accept failed", "rule", r.name(), "error", err)
				}
				return
			}
			source, ok := tcpSourceAddress(client.RemoteAddr())
			if !ok || !r.resources.reserveTCP(r.budget, source, r.rule.MaxTCPConnections, r.rule.MaxTCPConnectionsPerIP) {
				r.stats.tcpRejected.Add(1)
				_ = client.Close()
				continue
			}
			active.Store(client, struct{}{})
			r.stats.activeTCP.Add(1)
			r.stats.totalTCP.Add(1)
			r.wg.Add(1)
			go func() {
				defer r.wg.Done()
				defer active.Delete(client)
				defer r.stats.activeTCP.Add(-1)
				defer r.resources.releaseTCP(r.budget, source)
				defer client.Close()
				r.handleTCPWithBackup(client, &active, target, backup, health, dialer)
			}()
		}
	}()
	return nil
}

func (r *runner) handleTCP(client net.Conn, active *sync.Map, target string, dialer *net.Dialer) {
	r.handleTCPWithBackup(client, active, target, "", nil, dialer)
}

func (r *runner) handleTCPWithBackup(client net.Conn, active *sync.Map, target, backup string, health *tcpTargetState, dialer *net.Dialer) {
	upstream, usedBackup, err := r.dialTCPBackend(target, backup, health, dialer)
	if err != nil {
		r.logger.Debug("TCP target connect failed", "rule", r.name(), "client", client.RemoteAddr(), "target", target, "error", err)
		return
	}
	if usedBackup {
		r.stats.tcpFallbacks.Add(1)
	}
	active.Store(upstream, struct{}{})
	defer active.Delete(upstream)
	defer upstream.Close()
	meter := r.stats.beginTCPMeter(client, upstream)
	stopIdleMonitor := monitorTCPIdle(r.ctx, time.Duration(r.rule.TCPIdleTimeoutSeconds)*time.Second, client, upstream)
	defer stopIdleMonitor()
	uploadDone := make(chan int64, 1)
	go func() {
		n, copyErr := copyTCPStream(upstream, client)
		if meter != nil {
			meter.upDone.Store(n)
		}
		if copyErr != nil {
			// A failed direction cannot complete by half-closing alone: wake
			// the reverse copy so the existing deferred reservations return.
			_ = upstream.Close()
			_ = client.Close()
		} else {
			closeWrite(upstream)
		}
		uploadDone <- n
	}()
	down, copyErr := copyTCPStream(client, upstream)
	if meter != nil {
		meter.downDone.Store(down)
	}
	if copyErr != nil {
		_ = upstream.Close()
		_ = client.Close()
	} else {
		// Normal EOF still permits the peer to finish the other direction.
		closeWrite(client)
	}
	up := <-uploadDone
	r.stats.mu.Lock()
	delete(r.stats.liveTCP, meter)
	if up > 0 {
		r.stats.bytesUp.Add(uint64(up)) // #nosec G115 -- io.Copy byte counts are non-negative and checked above.
	}
	if down > 0 {
		r.stats.bytesDown.Add(uint64(down)) // #nosec G115 -- io.Copy byte counts are non-negative and checked above.
	}
	r.stats.mu.Unlock()
}

func (r *runner) dialTCPBackend(primary, backup string, health *tcpTargetState, dialer *net.Dialer) (net.Conn, bool, error) {
	if backup == "" {
		conn, err := dialer.DialContext(r.ctx, "tcp", primary)
		return conn, false, err
	}
	backupFirst := health != nil && health.checkedUnixNano.Load() != 0 && !health.primaryReachable.Load() && health.backupReachable.Load()
	first, second := primary, backup
	if backupFirst {
		first, second = backup, primary
	}
	conn, firstErr := dialer.DialContext(r.ctx, "tcp", first)
	if firstErr == nil {
		return conn, first == backup, nil
	}
	if r.ctx.Err() != nil {
		return nil, false, firstErr
	}
	conn, secondErr := dialer.DialContext(r.ctx, "tcp", second)
	if secondErr == nil {
		return conn, second == backup, nil
	}
	return nil, false, errors.Join(firstErr, secondErr)
}

func tcpSourceAddress(address net.Addr) (netip.Addr, bool) {
	if tcp, ok := address.(*net.TCPAddr); ok {
		return tcp.AddrPort().Addr().Unmap(), true
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

// copyTCPStream keeps *net.TCPConn unwrapped so its ReaderFrom implementation
// can use the platform fast path (splice on Linux). Non-TCP wrappers reuse a
// bounded buffer instead of allocating one for every copy direction.
func copyTCPStream(dst net.Conn, src net.Conn) (int64, error) {
	if fast, ok := dst.(readerFrom); ok {
		return fast.ReadFrom(src)
	}

	buffer := tcpCopyBufferPool.Get().(*[]byte)
	defer tcpCopyBufferPool.Put(buffer)
	return io.CopyBuffer(dst, src, *buffer)
}

func closeWrite(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
}

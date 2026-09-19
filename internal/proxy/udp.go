package proxy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"portbridge/internal/config"
)

const (
	udpMaintenanceInterval = 250 * time.Millisecond
	udpWheelSlots          = 512
	maxAutomaticUDPWorkers = 16
)

var (
	errUDPSessionLimit = errors.New("maximum UDP sessions reached")
	errUDPNoProgress   = errors.New("UDP batch write made no progress")
	errUDPBatchCount   = errors.New("UDP batch operation returned an invalid packet count")
)

type udpBatchConn interface {
	ReadBatch([]ipv4.Message, int) (int, error)
	WriteBatch([]ipv4.Message, int) (int, error)
}

type udpEndpoint struct {
	once    sync.Once
	workers []*udpWorker
}

type udpWorker struct {
	runner           *runner
	inbound          *net.UDPConn
	inboundBatch     udpBatchConn
	inboundFD        int
	epollFD          int
	target           *net.UDPAddr
	targetIPv6       bool
	inboundIPv6      bool
	packetInfo       bool
	maxSessions      int
	sessionBytes     int
	idleSeconds      int64
	sourceLimits     udpSourceLimits
	listenerReserved int64
	stopped          atomic.Bool

	sessions      map[netip.AddrPort]*udpSession
	localSessions map[udpFlowKey]*udpSession
	sessionsByFD  map[int]*udpSession
	wheel         []*udpSession
	wheelSecond   int64

	readMessages     []ipv4.Message
	responseMessages []ipv4.Message
	sendMessages     []ipv4.Message
	packetNext       []int
	activeSessions   []*udpSession
	batchEpoch       uint64
	events           []unix.EpollEvent

	bytesUp     uint64
	bytesDown   uint64
	packetsUp   uint64
	packetsDown uint64
	drops       uint64
}

type udpSession struct {
	client        netip.AddrPort
	clientAddr    *net.UDPAddr
	local         udpLocalEndpoint
	replyOOB      []byte
	outbound      *net.UDPConn
	batch         udpBatchConn
	fd            int
	expiresAt     int64
	closed        bool
	wheelSlot     int
	wheelPrev     *udpSession
	wheelNext     *udpSession
	batchEpoch    uint64
	batchHead     int
	batchTail     int
	reservedBytes int64
}

func (r *runner) startUDP(ep listenEndpoint, targetPort, workerCount, totalWorkerCount int) error {
	rule := config.NormalizeRule(r.rule)
	if targetPort < 1 || targetPort > 65535 {
		return fmt.Errorf("UDP target port must be 1-65535")
	}
	if workerCount < 1 || totalWorkerCount < 1 {
		return fmt.Errorf("UDP worker counts must be positive")
	}
	targetIP, err := netip.ParseAddr(rule.TargetHost)
	if err != nil {
		return fmt.Errorf("UDP target must be resolved before runner start: %w", err)
	}
	target := net.UDPAddrFromAddrPort(netip.AddrPortFrom(targetIP, uint16(targetPort))) // #nosec G115 -- targetPort is range-checked above.
	endpoint := &udpEndpoint{workers: make([]*udpWorker, 0, workerCount)}

	for workerID := 0; workerID < workerCount; workerID++ {
		listenerReserved := int64(rule.UDPListenerBufferBytes)*4 + int64(rule.UDPBatchSize*rule.UDPPacketBufferSize*2) + 64*1024
		listenIP, _ := netip.ParseAddr(rule.ListenHost)
		if rule.ListenHost == "*" || listenIP.IsUnspecified() {
			listenerReserved += udpWildcardMemory(rule.MaxUDPSessions, totalWorkerCount, rule.UDPBatchSize, ep.network == "udp6")
		}
		if !r.resources.reserveUDPMemory(listenerReserved) {
			endpoint.close()
			return fmt.Errorf("start UDP worker %d/%d: global UDP memory budget reached", workerID+1, workerCount)
		}
		conn, err := listenUDPWorker(r.ctx, ep.network, ep.address, workerCount > 1, rule.UDPListenerBufferBytes)
		if err != nil {
			r.resources.releaseUDPMemory(listenerReserved)
			endpoint.close()
			return fmt.Errorf("start UDP worker %d/%d: %w", workerID+1, workerCount, err)
		}
		worker, err := newUDPWorker(r, conn, ep.network == "udp6", target, rule, totalWorkerCount)
		if err != nil {
			_ = conn.Close()
			r.resources.releaseUDPMemory(listenerReserved)
			endpoint.close()
			return fmt.Errorf("initialize UDP worker %d/%d: %w", workerID+1, workerCount, err)
		}
		worker.listenerReserved = listenerReserved
		endpoint.workers = append(endpoint.workers, worker)
		r.wg.Add(1)
		go worker.serve()
	}

	r.addCloser(endpoint.close)
	r.logger.Debug("high-performance UDP endpoint started",
		"rule", r.rule.Name,
		"listen", ep.address,
		"workers", workerCount,
		"rule_workers", totalWorkerCount,
		"batch", rule.UDPBatchSize,
		"packet_buffer", rule.UDPPacketBufferSize)
	return nil
}

func effectiveUDPWorkers(configured int) int {
	if configured > 0 {
		return configured
	}
	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		workers = 1
	}
	if workers > maxAutomaticUDPWorkers {
		workers = maxAutomaticUDPWorkers
	}
	return workers
}

func newUDPWorker(r *runner, inbound *net.UDPConn, inboundIPv6 bool, target *net.UDPAddr, rule config.Rule, totalWorkerCount int) (*udpWorker, error) {
	batch := newUDPBatchConn(inbound, inboundIPv6)
	packetInfo := inbound.LocalAddr().(*net.UDPAddr).AddrPort().Addr().IsUnspecified()
	if packetInfo {
		if err := enableUDPPacketInfo(batch, inboundIPv6); err != nil {
			return nil, fmt.Errorf("enable UDP destination packet information: %w", err)
		}
	}
	epollFD, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, err
	}
	inboundFD, err := addUDPConnToEpoll(epollFD, inbound)
	if err != nil {
		_ = unix.Close(epollFD)
		return nil, err
	}

	capacity := udpInitialSessionCapacity(rule.MaxUDPSessions, totalWorkerCount)
	w := &udpWorker{
		runner:       r,
		inbound:      inbound,
		inboundBatch: batch,
		inboundIPv6:  inboundIPv6,
		packetInfo:   packetInfo,
		inboundFD:    inboundFD,
		epollFD:      epollFD,
		target:       target,
		targetIPv6:   target.IP.To4() == nil,
		maxSessions:  rule.MaxUDPSessions,
		sessionBytes: rule.UDPSessionBufferBytes,
		idleSeconds:  int64(rule.UDPIdleTimeoutSeconds),
		sourceLimits: udpSourceLimits{
			maxSessions:      rule.MaxUDPSessionsPerIP,
			newSessionsRate:  rule.UDPNewSessionsPerSec,
			packetRate:       rule.UDPPacketsPerSec,
			maxTrackedSource: maxTrackedUDPSources(rule.MaxUDPSessions),
		},
		sessionsByFD: make(map[int]*udpSession, capacity),
		wheel:        make([]*udpSession, udpWheelSlots),
		wheelSecond:  time.Now().Unix(),
		events:       make([]unix.EpollEvent, rule.UDPBatchSize+1),
	}
	if packetInfo {
		w.localSessions = make(map[udpFlowKey]*udpSession, capacity)
	} else {
		// Explicit binds retain the existing small AddrPort lookup path.
		w.sessions = make(map[netip.AddrPort]*udpSession, capacity)
	}
	w.readMessages = makeUDPMessages(rule.UDPBatchSize, rule.UDPPacketBufferSize, inboundIPv6)
	if packetInfo {
		addUDPPacketInfoBuffers(w.readMessages, inboundIPv6)
	}
	w.responseMessages = makeUDPMessages(rule.UDPBatchSize, rule.UDPPacketBufferSize, w.targetIPv6)
	w.sendMessages = makeUDPSendMessages(rule.UDPBatchSize)
	w.packetNext = make([]int, rule.UDPBatchSize)
	w.activeSessions = make([]*udpSession, 0, rule.UDPBatchSize)
	return w, nil
}

func maxTrackedUDPSources(maxSessions int) int {
	maximum := maxSessions * 2
	if maximum < 1024 {
		return 1024
	}
	if maximum > 65536 {
		return 65536
	}
	return maximum
}

func newUDPBatchConn(conn *net.UDPConn, ipv6Socket bool) udpBatchConn {
	if ipv6Socket {
		return ipv6.NewPacketConn(conn)
	}
	return ipv4.NewPacketConn(conn)
}

func makeUDPMessages(batchSize, packetSize int, ipv6Address bool) []ipv4.Message {
	messages := make([]ipv4.Message, batchSize)
	slab := make([]byte, batchSize*packetSize)
	ipLength := net.IPv4len
	if ipv6Address {
		ipLength = net.IPv6len
	}
	for i := range messages {
		packet := slab[i*packetSize : (i+1)*packetSize]
		messages[i].Buffers = [][]byte{packet}
		messages[i].Addr = &net.UDPAddr{IP: make(net.IP, ipLength)}
	}
	return messages
}

func makeUDPSendMessages(batchSize int) []ipv4.Message {
	messages := make([]ipv4.Message, batchSize)
	for i := range messages {
		messages[i].Buffers = [][]byte{nil}
	}
	return messages
}

func addUDPConnToEpoll(epollFD int, conn *net.UDPConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	fd := -1
	var controlErr error
	err = raw.Control(func(rawFD uintptr) {
		if rawFD > uintptr(1<<31-1) {
			controlErr = fmt.Errorf("UDP file descriptor exceeds epoll event range: %d", rawFD)
			return
		}
		fd = int(rawFD)
		controlErr = unix.EpollCtl(epollFD, unix.EPOLL_CTL_ADD, fd, &unix.EpollEvent{
			Events: uint32(unix.EPOLLIN | unix.EPOLLERR | unix.EPOLLHUP),
			Fd:     int32(fd), // #nosec G115 -- rawFD is checked against the signed 32-bit epoll ABI above.
		})
	})
	if err != nil {
		return 0, err
	}
	if controlErr != nil {
		return 0, controlErr
	}
	return fd, nil
}

func (u *udpEndpoint) close() {
	u.once.Do(func() {
		for _, worker := range u.workers {
			worker.stop()
		}
	})
}

func (w *udpWorker) stop() {
	if w.stopped.CompareAndSwap(false, true) {
		_ = w.inbound.Close()
	}
}

func (w *udpWorker) serve() {
	defer w.runner.wg.Done()
	defer w.cleanup()
	nextMaintenance := time.Now().Add(udpMaintenanceInterval)

	for !w.stopped.Load() && w.runner.ctx.Err() == nil {
		timeout := time.Until(nextMaintenance)
		if timeout < 0 {
			timeout = 0
		}
		timeoutMS := int(timeout / time.Millisecond)
		if timeoutMS < 1 {
			timeoutMS = 1
		}
		n, err := unix.EpollWait(w.epollFD, w.events, timeoutMS)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if w.stopped.Load() || w.runner.ctx.Err() != nil || errors.Is(err, unix.EBADF) {
				return
			}
			w.runner.logger.Warn("UDP epoll wait failed", "rule", w.runner.rule.Name, "error", err)
			return
		}

		now := time.Now()
		for i := 0; i < n; i++ {
			fd := int(w.events[i].Fd)
			if fd == w.inboundFD {
				if err := w.readInbound(now); err != nil && !isWouldBlock(err) {
					if w.stopped.Load() || w.runner.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
						return
					}
					w.runner.logger.Warn("UDP batch read failed", "rule", w.runner.rule.Name, "error", err)
					return
				}
				continue
			}
			session := w.sessionsByFD[fd]
			if session == nil || session.closed {
				continue
			}
			if err := w.readResponses(session, now); err != nil && !isWouldBlock(err) {
				w.closeSession(session)
			}
		}

		if !now.Before(nextMaintenance) {
			w.maintain(now)
			nextMaintenance = now.Add(udpMaintenanceInterval)
		}
	}
}

func (w *udpWorker) readInbound(now time.Time) error {
	n, readErr := w.inboundBatch.ReadBatch(w.readMessages, unix.MSG_DONTWAIT)
	if n == -1 && readErr != nil {
		n = 0
	}
	if n < 0 || n > len(w.readMessages) {
		return fmt.Errorf("%w: read returned %d for capacity %d", errUDPBatchCount, n, len(w.readMessages))
	}
	w.beginPacketBatch()
	for i := 0; i < n; i++ {
		message := &w.readMessages[i]
		if message.N < 0 || len(message.Buffers) != 1 || message.N > len(message.Buffers[0]) || message.Flags&unix.MSG_TRUNC != 0 {
			w.drops++
			continue
		}
		clientAddr, ok := message.Addr.(*net.UDPAddr)
		if !ok {
			w.drops++
			continue
		}
		client := clientAddr.AddrPort()
		if !client.IsValid() {
			w.drops++
			continue
		}
		client = netip.AddrPortFrom(client.Addr().Unmap(), client.Port())
		var local udpLocalEndpoint
		session := w.sessions[client]
		if w.packetInfo {
			var err error
			local, err = parseUDPLocalEndpoint(message, w.inboundIPv6)
			if err != nil {
				w.drops++
				continue
			}
			local = local.forClient(client)
			session = w.localSessions[udpFlowKey{client: client, local: local}]
		}
		newSession := session == nil
		if !w.runner.budget.reserveUDPPacket(client.Addr(), newSession, now, w.sourceLimits) {
			w.drops++
			continue
		}
		if newSession {
			var err error
			session, err = w.newSession(client, local, now)
			if err != nil {
				w.runner.budget.rollbackUDPSourceSession(client.Addr(), w.sourceLimits.newSessionsRate)
				w.drops++
				continue
			}
		}
		w.queuePacket(i, session)
	}

	for _, session := range w.activeSessions {
		count := 0
		for i := session.batchHead; i >= 0; i = w.packetNext[i] {
			message := &w.readMessages[i]
			prepareUDPSend(&w.sendMessages[count], message.Buffers[0][:message.N], nil, nil)
			count++
		}
		sent, err := writeUDPBatch(session.batch, w.sendMessages[:count])
		for i := 0; i < sent; i++ {
			w.bytesUp += uint64(len(w.sendMessages[i].Buffers[0]))
		}
		w.packetsUp += uint64(sent) // #nosec G115 -- writeUDPBatch guarantees 0 <= sent <= count.
		if sent < count {
			w.drops += uint64(count - sent) // #nosec G115 -- writeUDPBatch guarantees sent <= count.
		}
		for i := 0; i < count; i++ {
			prepareUDPSend(&w.sendMessages[i], nil, nil, nil)
		}
		if sent > 0 {
			w.touchSession(session, now)
		}
		if err != nil && !isUDPTransientSendError(err) {
			w.closeSession(session)
		}
	}

	for i := range w.activeSessions {
		w.activeSessions[i] = nil
	}
	w.activeSessions = w.activeSessions[:0]
	for i := 0; i < n; i++ {
		w.readMessages[i].N = 0
		w.readMessages[i].NN = 0
		w.readMessages[i].Flags = 0
	}
	return readErr
}

// beginPacketBatch creates a generation for worker-local, allocation-free
// grouping. It allows interleaved packets for the same flow to share one
// sendmmsg call without building a temporary map on the hot path.
func (w *udpWorker) beginPacketBatch() {
	for i := range w.activeSessions {
		w.activeSessions[i] = nil
	}
	w.activeSessions = w.activeSessions[:0]
	w.batchEpoch++
	if w.batchEpoch == 0 {
		w.batchEpoch = 1
		for _, session := range w.sessions {
			session.batchEpoch = 0
		}
		for _, session := range w.localSessions {
			session.batchEpoch = 0
		}
	}
}

func (w *udpWorker) queuePacket(index int, session *udpSession) {
	w.packetNext[index] = -1
	if session.batchEpoch != w.batchEpoch {
		session.batchEpoch = w.batchEpoch
		session.batchHead = index
		session.batchTail = index
		w.activeSessions = append(w.activeSessions, session)
		return
	}
	w.packetNext[session.batchTail] = index
	session.batchTail = index
}

func (w *udpWorker) readResponses(session *udpSession, now time.Time) error {
	n, readErr := session.batch.ReadBatch(w.responseMessages, unix.MSG_DONTWAIT)
	if n == -1 && readErr != nil {
		n = 0
	}
	if n < 0 || n > len(w.responseMessages) {
		return fmt.Errorf("%w: read returned %d for capacity %d", errUDPBatchCount, n, len(w.responseMessages))
	}
	count := 0
	for i := 0; i < n; i++ {
		message := &w.responseMessages[i]
		if message.N < 0 || len(message.Buffers) != 1 || message.N > len(message.Buffers[0]) || message.Flags&unix.MSG_TRUNC != 0 {
			w.drops++
			continue
		}
		prepareUDPSend(&w.sendMessages[count], message.Buffers[0][:message.N], session.clientAddr, session.replyOOB)
		count++
	}

	sent, writeErr := writeUDPBatch(w.inboundBatch, w.sendMessages[:count])
	for i := 0; i < sent; i++ {
		w.bytesDown += uint64(len(w.sendMessages[i].Buffers[0]))
	}
	w.packetsDown += uint64(sent) // #nosec G115 -- writeUDPBatch guarantees 0 <= sent <= count.
	if sent < count {
		w.drops += uint64(count - sent) // #nosec G115 -- writeUDPBatch guarantees sent <= count.
	}
	for i := 0; i < count; i++ {
		prepareUDPSend(&w.sendMessages[i], nil, nil, nil)
	}
	for i := 0; i < n; i++ {
		w.responseMessages[i].N = 0
		w.responseMessages[i].NN = 0
		w.responseMessages[i].Flags = 0
	}
	if sent > 0 {
		w.touchSession(session, now)
	}
	if writeErr != nil && !isUDPTransientSendError(writeErr) {
		return writeErr
	}
	return readErr
}

func writeUDPBatch(conn udpBatchConn, messages []ipv4.Message) (int, error) {
	written := 0
	for written < len(messages) {
		n, err := conn.WriteBatch(messages[written:], unix.MSG_DONTWAIT)
		if n == -1 && err != nil {
			n = 0
		}
		if n < 0 || n > len(messages)-written {
			return written, fmt.Errorf("%w: write returned %d for remaining capacity %d", errUDPBatchCount, n, len(messages)-written)
		}
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, errUDPNoProgress
		}
	}
	return written, nil
}

func (w *udpWorker) newSession(client netip.AddrPort, local udpLocalEndpoint, now time.Time) (*udpSession, error) {
	if !reserveUDPSession(w.runner.stats, w.maxSessions) {
		return nil, errUDPSessionLimit
	}
	reservedBytes := int64(w.sessionBytes)*4 + 4096 + udpLocalSessionMetadataReserve
	if w.packetInfo {
		reservedBytes += udpWildcardSessionReserve
	}
	if !w.runner.resources.reserveUDP(reservedBytes) {
		w.runner.stats.activeUDP.Add(-1)
		return nil, errUDPSessionLimit
	}
	reserved := true
	defer func() {
		if reserved {
			w.runner.stats.activeUDP.Add(-1)
			w.runner.resources.releaseUDP(reservedBytes)
		}
	}()

	network := "udp4"
	if w.targetIPv6 {
		network = "udp6"
	}
	outbound, err := net.DialUDP(network, nil, w.target)
	if err != nil {
		return nil, err
	}
	if size := w.sessionBytes; size > 0 {
		if err := outbound.SetReadBuffer(size); err != nil {
			_ = outbound.Close()
			return nil, err
		}
		if err := outbound.SetWriteBuffer(size); err != nil {
			_ = outbound.Close()
			return nil, err
		}
	}
	fd, err := addUDPConnToEpoll(w.epollFD, outbound)
	if err != nil {
		_ = outbound.Close()
		return nil, err
	}

	session := &udpSession{
		client:        client,
		local:         local,
		clientAddr:    net.UDPAddrFromAddrPort(client),
		outbound:      outbound,
		batch:         newUDPBatchConn(outbound, w.targetIPv6),
		fd:            fd,
		wheelSlot:     -1,
		reservedBytes: reservedBytes,
	}
	if w.packetInfo {
		session.replyOOB = udpReplyPacketInfo(local, w.inboundIPv6)
		w.localSessions[udpFlowKey{client: client, local: local}] = session
	} else {
		w.sessions[client] = session
	}
	w.sessionsByFD[fd] = session
	w.touchSession(session, now)
	w.runner.stats.totalUDP.Add(1)
	reserved = false
	return session, nil
}

func reserveUDPSession(stats *Stats, maximum int) bool {
	for {
		current := stats.activeUDP.Load()
		if current >= int64(maximum) {
			return false
		}
		if stats.activeUDP.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

func (w *udpWorker) touchSession(session *udpSession, now time.Time) {
	session.expiresAt = now.Unix() + w.idleSeconds
	if session.wheelSlot < 0 {
		w.insertWheel(session)
	}
}

func (w *udpWorker) insertWheel(session *udpSession) {
	slot := int(session.expiresAt % int64(len(w.wheel)))
	session.wheelSlot = slot
	session.wheelPrev = nil
	session.wheelNext = w.wheel[slot]
	if session.wheelNext != nil {
		session.wheelNext.wheelPrev = session
	}
	w.wheel[slot] = session
}

func (w *udpWorker) removeWheel(session *udpSession) {
	if session.wheelSlot < 0 {
		return
	}
	if session.wheelPrev != nil {
		session.wheelPrev.wheelNext = session.wheelNext
	} else if w.wheel[session.wheelSlot] == session {
		w.wheel[session.wheelSlot] = session.wheelNext
	}
	if session.wheelNext != nil {
		session.wheelNext.wheelPrev = session.wheelPrev
	}
	session.wheelSlot = -1
	session.wheelPrev = nil
	session.wheelNext = nil
}

func (w *udpWorker) maintain(now time.Time) {
	nowSecond := now.Unix()
	steps := nowSecond - w.wheelSecond
	if steps > int64(len(w.wheel)) {
		steps = int64(len(w.wheel))
		w.wheelSecond = nowSecond - steps
	}
	for w.wheelSecond < nowSecond {
		w.wheelSecond++
		w.expireWheelSlot(w.wheelSecond)
	}
	w.runner.budget.maintainUDPSources(now, time.Duration(w.idleSeconds)*time.Second)
	w.flushStats()
}

func (w *udpWorker) expireWheelSlot(second int64) {
	slot := int(second % int64(len(w.wheel)))
	for session := w.wheel[slot]; session != nil; {
		next := session.wheelNext
		w.removeWheel(session)
		if !session.closed {
			if session.expiresAt <= second {
				w.closeSession(session)
			} else {
				w.insertWheel(session)
			}
		}
		session = next
	}
}

func (w *udpWorker) closeSession(session *udpSession) {
	if session == nil || session.closed {
		return
	}
	session.closed = true
	w.removeWheel(session)
	_ = unix.EpollCtl(w.epollFD, unix.EPOLL_CTL_DEL, session.fd, nil)
	if w.packetInfo {
		delete(w.localSessions, udpFlowKey{client: session.client, local: session.local})
	} else {
		delete(w.sessions, session.client)
	}
	delete(w.sessionsByFD, session.fd)
	_ = session.outbound.Close()
	w.runner.budget.releaseUDPSourceSession(session.client.Addr(), time.Now())
	w.runner.stats.activeUDP.Add(-1)
	w.runner.resources.releaseUDP(session.reservedBytes)
}

func (w *udpWorker) flushStats() {
	if w.bytesUp != 0 {
		w.runner.stats.bytesUp.Add(w.bytesUp)
		w.bytesUp = 0
	}
	if w.bytesDown != 0 {
		w.runner.stats.bytesDown.Add(w.bytesDown)
		w.bytesDown = 0
	}
	if w.packetsUp != 0 {
		w.runner.stats.udpUp.Add(w.packetsUp)
		w.packetsUp = 0
	}
	if w.packetsDown != 0 {
		w.runner.stats.udpDown.Add(w.packetsDown)
		w.packetsDown = 0
	}
	if w.drops != 0 {
		w.runner.stats.udpDrops.Add(w.drops)
		w.drops = 0
	}
}

func (w *udpWorker) cleanup() {
	for _, session := range w.sessions {
		w.closeSession(session)
	}
	for _, session := range w.localSessions {
		w.closeSession(session)
	}
	w.flushStats()
	_ = w.inbound.Close()
	_ = unix.Close(w.epollFD)
	w.runner.resources.releaseUDPMemory(w.listenerReserved)
}

func isWouldBlock(err error) bool {
	return errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK)
}

func isUDPTransientSendError(err error) bool {
	return isWouldBlock(err) || errors.Is(err, unix.ENOBUFS) || errors.Is(err, unix.ENOMEM) || errors.Is(err, unix.EINTR)
}

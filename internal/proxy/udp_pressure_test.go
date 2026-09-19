//go:build linux

package proxy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

type pressureBatchFixture struct {
	incoming []ipv4.Message
	written  int
	failure  error
}

func (f *pressureBatchFixture) ReadBatch(messages []ipv4.Message, _ int) (int, error) {
	n := copy(messages, f.incoming)
	f.incoming = nil
	return n, nil
}

func (f *pressureBatchFixture) WriteBatch(messages []ipv4.Message, _ int) (int, error) {
	if f.failure != nil {
		return f.written, f.failure
	}
	return len(messages), nil
}

func TestUDPTransientSendPressurePreservesSession(t *testing.T) {
	for _, errno := range []error{unix.ENOBUFS, unix.ENOMEM, unix.EINTR, unix.EAGAIN} {
		for _, response := range []bool{false, true} {
			for _, sent := range []int{-1, 0, 1} {
				t.Run(fmt.Sprintf("%v/response=%t/partial=%d", errno, response, sent), func(t *testing.T) {
					w := repairManualWorker(t)
					w.packetInfo = false
					w.sessions = make(map[netip.AddrPort]*udpSession)
					client := netip.MustParseAddrPort("127.0.0.1:45000")
					now := time.Now()
					session := repairManualSession(t, w, client, udpLocalEndpoint{}, now)
					memory := w.runner.resources.udpMemory.Load()
					packets := []ipv4.Message{
						{Buffers: [][]byte{[]byte("a")}, N: 1, Addr: net.UDPAddrFromAddrPort(client)},
						{Buffers: [][]byte{[]byte("b")}, N: 1, Addr: net.UDPAddrFromAddrPort(client)},
					}
					inbound, upstream := &pressureBatchFixture{}, &pressureBatchFixture{}
					w.inboundBatch, session.batch = inbound, upstream
					failure := fmt.Errorf("injected socket pressure: %w", errno)
					var err error
					if response {
						upstream.incoming = packets
						inbound.written, inbound.failure = sent, failure
						err = w.readResponses(session, now)
						if err != nil && !isWouldBlock(err) {
							w.closeSession(session)
						}
					} else {
						inbound.incoming = packets
						upstream.written, upstream.failure = sent, failure
						err = w.readInbound(now)
					}
					if session.closed || w.sessions[client] != session || w.runner.stats.activeUDP.Load() != 1 || w.runner.stats.totalUDP.Load() != 1 || w.runner.resources.udpMemory.Load() != memory {
						t.Fatalf("transient send pressure destroyed/reallocated a live session: err=%v closed=%t", err, session.closed)
					}
					accepted := sent
					if accepted < 0 {
						accepted = 0
					}
					if w.drops != uint64(2-accepted) {
						t.Fatalf("unsent packets not counted exactly: drops=%d", w.drops)
					}
					inbound.failure, upstream.failure = nil, nil
					if response {
						upstream.incoming = packets[:1]
						err = w.readResponses(session, now.Add(time.Millisecond))
					} else {
						inbound.incoming = packets[:1]
						err = w.readInbound(now.Add(time.Millisecond))
					}
					if err != nil || session.closed || w.runner.stats.totalUDP.Load() != 1 {
						t.Fatalf("same session did not recover: %v", err)
					}
				})
			}
		}
	}
}

func TestUDPFatalSendErrorStillClosesSession(t *testing.T) {
	w := repairManualWorker(t)
	w.packetInfo = false
	w.sessions = make(map[netip.AddrPort]*udpSession)
	client := netip.MustParseAddrPort("127.0.0.1:45000")
	session := repairManualSession(t, w, client, udpLocalEndpoint{}, time.Now())
	w.inboundBatch = &pressureBatchFixture{incoming: []ipv4.Message{{Buffers: [][]byte{[]byte("x")}, N: 1, Addr: net.UDPAddrFromAddrPort(client)}}}
	session.batch = &pressureBatchFixture{written: -1, failure: unix.EBADF}
	if err := w.readInbound(time.Now()); err != nil {
		t.Fatal(err)
	}
	if !session.closed || w.runner.stats.activeUDP.Load() != 0 {
		t.Fatal("fatal descriptor failure was silently retained")
	}
}

type syscallFailureBatch struct{}

func (*syscallFailureBatch) ReadBatch([]ipv4.Message, int) (int, error) {
	return -1, fmt.Errorf("recvmmsg: %w", unix.EAGAIN)
}

func (*syscallFailureBatch) WriteBatch([]ipv4.Message, int) (int, error) {
	return -1, fmt.Errorf("sendmmsg: %w", unix.EAGAIN)
}

func TestUDPBatchSyscallFailureSentinel(t *testing.T) {
	batch := &syscallFailureBatch{}
	written, err := writeUDPBatch(batch, makeUDPMessages(2, 64, false))
	if written != 0 || !errors.Is(err, unix.EAGAIN) || errors.Is(err, errUDPBatchCount) {
		t.Errorf("write lost syscall error: n=%d err=%v", written, err)
	}
	w := repairManualWorker(t)
	w.inboundBatch = batch
	if err := w.readInbound(time.Now()); !errors.Is(err, unix.EAGAIN) || errors.Is(err, errUDPBatchCount) {
		t.Errorf("listener read lost syscall error: %v", err)
	}
	session := &udpSession{batch: batch}
	if err := w.readResponses(session, time.Now()); !errors.Is(err, unix.EAGAIN) || errors.Is(err, errUDPBatchCount) {
		t.Errorf("upstream read lost syscall error: %v", err)
	}
}

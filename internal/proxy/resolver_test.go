package proxy

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func startTestDNSServer(t *testing.T) (string, func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, peer, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			request := append([]byte(nil), buf[:n]...)
			if len(request) < 17 {
				continue
			}
			pos := 12
			for pos < len(request) && request[pos] != 0 {
				pos += int(request[pos]) + 1
			}
			if pos+5 > len(request) {
				continue
			}
			pos++
			questionEnd := pos + 4
			queryType := binary.BigEndian.Uint16(request[pos : pos+2])
			answerCount := uint16(0)
			if queryType == 1 {
				answerCount = 1
			}
			response := make([]byte, 12)
			copy(response[:2], request[:2])
			binary.BigEndian.PutUint16(response[2:4], 0x8180)
			binary.BigEndian.PutUint16(response[4:6], 1)
			binary.BigEndian.PutUint16(response[6:8], answerCount)
			response = append(response, request[12:questionEnd]...)
			if answerCount == 1 {
				response = append(response,
					0xc0, 0x0c,
					0x00, 0x01, 0x00, 0x01,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x04, 127, 0, 0, 1,
				)
			}
			_, _ = conn.WriteToUDP(response, peer)
		}
	}()
	return conn.LocalAddr().String(), func() { _ = conn.Close() }
}

func TestCustomDNSResolver(t *testing.T) {
	server, closeServer := startTestDNSServer(t)
	defer closeServer()
	custom := NewDNSResolver([]string{server})
	resolver := custom.Resolver()
	if resolver == nil {
		t.Fatal("custom resolver is nil")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addresses, err := resolver.LookupHost(ctx, "custom.portbridge.test")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, address := range addresses {
		if address == "127.0.0.1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("custom DNS returned %v", addresses)
	}
	custom.SetServers(nil)
	if custom.Resolver() != nil {
		t.Fatal("empty custom DNS should use the system resolver")
	}
}

func TestDNSRoundRobinCounterWrapDoesNotCreateNegativeIndex(t *testing.T) {
	custom := NewDNSResolver(nil)
	custom.next.Store(^uint64(0))
	conn, err := custom.dial(context.Background(), "udp", []string{"127.0.0.1:1", "127.0.0.1:2"})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

package proxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
)

type DNSResolver struct {
	mu      sync.RWMutex
	servers []string
	next    atomic.Uint64
}

func NewDNSResolver(servers []string) *DNSResolver {
	r := &DNSResolver{}
	r.SetServers(servers)
	return r
}

func (r *DNSResolver) SetServers(servers []string) {
	r.mu.Lock()
	r.servers = append([]string{}, servers...)
	r.mu.Unlock()
}

func (r *DNSResolver) Resolver() *net.Resolver {
	r.mu.RLock()
	servers := append([]string{}, r.servers...)
	r.mu.RUnlock()
	if len(servers) == 0 {
		return nil
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return r.dial(ctx, network, servers)
		},
	}
}

func (r *DNSResolver) LookupNetIP(ctx context.Context, host string) ([]netip.Addr, error) {
	resolver := r.Resolver()
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return resolver.LookupNetIP(ctx, "ip", host)
}

func (r *DNSResolver) dial(ctx context.Context, network string, servers []string) (net.Conn, error) {
	if len(servers) == 0 {
		return nil, errors.New("no custom DNS server is configured")
	}
	serverCount := uint64(len(servers))             // #nosec G115 -- len is non-negative and bounded by configuration validation.
	start := int((r.next.Add(1) - 1) % serverCount) // #nosec G115 -- modulo guarantees the result is smaller than len(servers).
	var lastErr error
	for i := range servers {
		server := servers[(start+i)%len(servers)]
		conn, err := (&net.Dialer{}).DialContext(ctx, network, server)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

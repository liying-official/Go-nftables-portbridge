package proxy

import (
	"context"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func linuxListenConfig(ipv6 bool) net.ListenConfig {
	return linuxListenConfigWithOptions(ipv6, false, 0)
}

func linuxListenConfigWithOptions(ipv6, reusePort bool, socketBufferBytes int) net.ListenConfig {
	return net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var controlErr error
			err := c.Control(func(fd uintptr) {
				if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); e != nil {
					controlErr = e
					return
				}
				if reusePort {
					if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); e != nil {
						controlErr = e
						return
					}
				}
				if socketBufferBytes > 0 {
					if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, socketBufferBytes); e != nil {
						controlErr = e
						return
					}
					if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, socketBufferBytes); e != nil {
						controlErr = e
						return
					}
				}
				if ipv6 {
					if e := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); e != nil {
						controlErr = e
					}
				}
			})
			if err != nil {
				return err
			}
			return controlErr
		},
		KeepAlive: 30 * time.Second,
	}
}

func listenTCP(ctx context.Context, network, address string) (net.Listener, error) {
	lc := linuxListenConfig(network == "tcp6")
	return lc.Listen(ctx, network, address)
}

func listenUDPWorker(ctx context.Context, network, address string, reusePort bool, socketBufferBytes int) (*net.UDPConn, error) {
	lc := linuxListenConfigWithOptions(network == "udp6", reusePort, socketBufferBytes)
	pc, err := lc.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

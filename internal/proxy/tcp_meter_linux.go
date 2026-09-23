//go:build linux

package proxy

import (
	"golang.org/x/sys/unix"
	"net"
)

func tcpBytesAcknowledged(conn net.Conn) (uint64, bool) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return 0, false
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return 0, false
	}
	var info *unix.TCPInfo
	var callErr error
	err = raw.Control(func(fd uintptr) { info, callErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO) })
	if err != nil || callErr != nil || info == nil {
		return 0, false
	}
	return info.Bytes_acked, true
}

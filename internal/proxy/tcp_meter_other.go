//go:build !linux

package proxy

import "net"

func tcpBytesAcknowledged(net.Conn) (uint64, bool) { return 0, false }

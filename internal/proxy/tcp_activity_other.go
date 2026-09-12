//go:build !linux

package proxy

import (
	"context"
	"net"
	"time"
)

func monitorTCPIdle(_ context.Context, timeout time.Duration, connections ...net.Conn) func() {
	for _, connection := range connections {
		_ = connection.SetDeadline(time.Now().Add(timeout))
	}
	return func() {}
}

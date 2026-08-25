package dialer

import (
	"net"
	"time"
)

const (
	tcpKeepAliveIdle     = 30 * time.Second
	tcpKeepAliveInterval = 15 * time.Second
	tcpKeepAliveCount    = 8
)

func tcpKeepAlive(c net.Conn) {
	for i := 0; i < 8 && c != nil; i++ {
		if tc, ok := c.(*net.TCPConn); ok {
			cfg := net.KeepAliveConfig{
				Enable:   true,
				Idle:     tcpKeepAliveIdle,
				Interval: tcpKeepAliveInterval,
				Count:    tcpKeepAliveCount,
			}
			if err := tc.SetKeepAliveConfig(cfg); err != nil {
				_ = tc.SetKeepAlive(true)
				_ = tc.SetKeepAlivePeriod(tcpKeepAliveIdle)
			}
			return
		}
		type netConner interface{ NetConn() net.Conn }
		if n, ok := c.(netConner); ok {
			c = n.NetConn()
			continue
		}
		return
	}
}

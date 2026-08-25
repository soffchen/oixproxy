package dialer

import (
	"net"
	"testing"
	"time"
)

func TestTCPKeepAliveOnTCPConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		time.Sleep(200 * time.Millisecond)
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tcpKeepAlive(c)
	tc := c.(*net.TCPConn)
	if err := tc.SetKeepAlive(true); err != nil {
		t.Fatal(err)
	}
}

func TestTCPKeepAliveIgnoresPipe(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	tcpKeepAlive(a)
}

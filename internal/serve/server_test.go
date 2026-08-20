package serve

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/soffchen/oixproxy/internal/dialer"
)

func TestMappedPortSOCKSCONNECT(t *testing.T) {
	var mu sync.Mutex
	var gotHost string
	var gotPort uint16
	var gotNode string
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpPort := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	pln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mapPort := pln.Addr().(*net.TCPAddr).Port
	_ = pln.Close()

	s := &Server{
		Listen:   net.JoinHostPort("127.0.0.1", strconv.Itoa(httpPort)),
		Bind:     "127.0.0.1",
		BasePort: mapPort,
		Nodes:    []dialer.Node{{Name: "🇭🇰 香港 Fusion 01", Server: "remote.example", Port: 443, PSK: "x", ECHConfig: "AAAA"}},
		Dial: func(ctx context.Context, n dialer.Node, network, host string, port uint16) (net.Conn, error) {
			mu.Lock()
			gotHost, gotPort, gotNode = host, port, n.Name
			mu.Unlock()
			a, b := net.Pipe()
			go func() {
				defer b.Close()
				buf := make([]byte, 16)
				n, _ := b.Read(buf)
				b.Write([]byte("OK" + string(buf[:n])))
			}()
			return a, nil
		},
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(mapPort)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	var greet [2]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil {
		t.Fatal(err)
	}
	host := "www.gstatic.com"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], 443)
	req = append(req, pb[:]...)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0 {
		t.Fatalf("socks reply %v", rep)
	}
	if _, err := c.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 16)
	n, _ := c.Read(out)
	if string(out[:n]) != "OKhi" {
		t.Fatalf("relay %q", out[:n])
	}
	mu.Lock()
	defer mu.Unlock()
	if gotHost != host || gotPort != 443 || gotNode != "🇭🇰 香港 Fusion 01" {
		t.Fatalf("dial %s %s:%d", gotNode, gotHost, gotPort)
	}
}

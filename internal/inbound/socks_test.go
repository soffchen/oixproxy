package inbound

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestSOCKS5CONNECTInvokesHandler(t *testing.T) {
	var mu sync.Mutex
	var gotHost string
	var gotPort uint16
	h := func(network, host string, port uint16) (net.Conn, error) {
		mu.Lock()
		gotHost, gotPort = host, port
		mu.Unlock()
		c1, c2 := net.Pipe()
		go func() {
			defer c2.Close()
			buf := make([]byte, 32)
			n, _ := c2.Read(buf)
			c2.Write([]byte("pong:" + string(buf[:n])))
		}()
		return c1, nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go AcceptLoop(ln, "", "", h)

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))

	// greeting: ver=5, 1 method, no-auth
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	var greet [2]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil {
		t.Fatal(err)
	}
	if greet != [2]byte{0x05, 0x00} {
		t.Fatalf("greet %v", greet)
	}
	// CONNECT example.com:443 domain
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len("example.com"))}
	req = append(req, "example.com"...)
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
	if rep[1] != 0x00 {
		t.Fatalf("reply %v", rep)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 16)
	n, err := c.Read(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(out[:n]) != "pong:ping" {
		t.Fatalf("relay %q", out[:n])
	}
	mu.Lock()
	defer mu.Unlock()
	if gotHost != "example.com" || gotPort != 443 {
		t.Fatalf("handler got %s:%d", gotHost, gotPort)
	}
}

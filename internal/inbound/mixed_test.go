package inbound

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func echoHandler(t *testing.T) (Handler, *sync.Mutex, *string) {
	t.Helper()
	var mu sync.Mutex
	var got string
	h := func(network, host string, port uint16) (net.Conn, error) {
		mu.Lock()
		got = host
		mu.Unlock()
		c1, c2 := net.Pipe()
		go func() {
			defer c2.Close()
			buf := make([]byte, 32)
			n, _ := c2.Read(buf)
			_, _ = c2.Write([]byte("pong:" + string(buf[:n])))
		}()
		return c1, nil
	}
	return h, &mu, &got
}

func TestHTTPNonCONNECTRejected(t *testing.T) {
	h, _, _ := echoHandler(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go AcceptLoop(ln, "", "", h, nil)

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(c, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if resp.Header.Get("Allow") != "CONNECT" {
		t.Fatalf("Allow %q", resp.Header.Get("Allow"))
	}
}

func TestHTTPCONNECTInvokesHandler(t *testing.T) {
	h, mu, got := echoHandler(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go AcceptLoop(ln, "", "", h, nil)

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
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
	if *got != "example.com" {
		t.Fatalf("handler %q", *got)
	}
}

func TestHTTPCONNECTAuthRequired(t *testing.T) {
	h, _, _ := echoHandler(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go AcceptLoop(ln, "alice", "secret", h, nil)

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestHTTPCONNECTAuthOK(t *testing.T) {
	h, _, _ := echoHandler(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go AcceptLoop(ln, "alice", "secret", h, nil)

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	token := base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	req := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic " + token + "\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestSOCKS5AuthRequired(t *testing.T) {
	h, _, _ := echoHandler(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go AcceptLoop(ln, "alice", "secret", h, nil)

	c, err := net.Dial("tcp", ln.Addr().String())
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
	if greet != [2]byte{0x05, 0xff} {
		t.Fatalf("greet %v, want no-acceptable", greet)
	}
}

func TestSOCKS5AuthRejectsBadPassword(t *testing.T) {
	h, _, _ := echoHandler(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go AcceptLoop(ln, "alice", "secret", h, nil)

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatal(err)
	}
	var greet [2]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil {
		t.Fatal(err)
	}
	if greet != [2]byte{0x05, 0x02} {
		t.Fatalf("greet %v", greet)
	}
	auth := []byte{0x01, 5}
	auth = append(auth, "alice"...)
	auth = append(auth, 4)
	auth = append(auth, "nope"...)
	if _, err := c.Write(auth); err != nil {
		t.Fatal(err)
	}
	var rep [2]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		t.Fatal(err)
	}
	if rep != [2]byte{0x01, 0x01} {
		t.Fatalf("auth rep %v", rep)
	}
}

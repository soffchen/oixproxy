package inbound

import (
	"bufio"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type writeErrorConn struct {
	net.Conn
	err error
}

func (c *writeErrorConn) Write([]byte) (int, error) { return 0, c.err }

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

func TestRelayCopyReturnsWriteError(t *testing.T) {
	want := errors.New("write failed")
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	err := relayCopy(&writeErrorConn{Conn: a, err: want}, strings.NewReader("payload"))
	if !errors.Is(err, want) {
		t.Fatalf("转发错误为 %v，期望 %v", err, want)
	}
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

func TestSOCKS5AuthSuccessRelays(t *testing.T) {
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
	auth = append(auth, 6)
	auth = append(auth, "secret"...)
	if _, err := c.Write(auth); err != nil {
		t.Fatal(err)
	}
	var authReply [2]byte
	if _, err := io.ReadFull(c, authReply[:]); err != nil {
		t.Fatal(err)
	}
	if authReply != [2]byte{0x01, 0x00} {
		t.Fatalf("auth reply %v", authReply)
	}
	host := "example.com"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, 0x01, 0xbb)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("connect reply %v", reply)
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
}

func TestSOCKS5RejectsUnofferedNoAuth(t *testing.T) {
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
	if _, err := c.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatal(err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		t.Fatal(err)
	}
	if reply != [2]byte{0x05, 0xff} {
		t.Fatalf("reply %v", reply)
	}
}

func TestHTTPConnectRejectsPortOverflow(t *testing.T) {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader("CONNECT example.com:65536 HTTP/1.1\r\nHost: example.com:65536\r\n\r\n")))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := splitHostPort(req.Host, 443); err == nil {
		t.Fatal("超过 65535 的 CONNECT 端口应被拒绝")
	}
}

func TestBasicSchemeIsCaseInsensitive(t *testing.T) {
	token := base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	u, p, ok := parseBasic("bAsIc " + token)
	if !ok || u != "alice" || p != "secret" {
		t.Fatalf("basic auth %q %q %v", u, p, ok)
	}
}

type temporaryTestError struct{}

func (temporaryTestError) Error() string   { return "temporary error" }
func (temporaryTestError) Timeout() bool   { return false }
func (temporaryTestError) Temporary() bool { return true }

type timeoutTestError struct{}

func (timeoutTestError) Error() string   { return "timeout error" }
func (timeoutTestError) Timeout() bool   { return true }
func (timeoutTestError) Temporary() bool { return false }

func TestRetryableNetworkError(t *testing.T) {
	if !retryableNetworkError(temporaryTestError{}) || !retryableNetworkError(timeoutTestError{}) {
		t.Fatal("临时或超时错误应重试")
	}
	if retryableNetworkError(errors.New("permanent")) {
		t.Fatal("永久错误不应重试")
	}
}

type retryTestListener struct {
	calls  atomic.Int32
	closed chan struct{}
	once   sync.Once
}

func (l *retryTestListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	default:
		l.calls.Add(1)
		return nil, temporaryTestError{}
	}
}

func (l *retryTestListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (*retryTestListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestAcceptLoopKeepsRetryingTemporaryErrors(t *testing.T) {
	ln := &retryTestListener{closed: make(chan struct{})}
	errCh := make(chan error, 1)
	go func() {
		errCh <- AcceptLoop(ln, "", "", nil, nil)
	}()
	select {
	case err := <-errCh:
		t.Logf("AcceptLoop err=%v", err)
		t.Fatalf("AcceptLoop 在 %d 次临时错误后退出", ln.calls.Load())
	case <-time.After(350 * time.Millisecond):
	}
	if ln.calls.Load() == 0 {
		t.Fatal("AcceptLoop 未调用 Accept")
	}
	_ = ln.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("关闭 listener 后 AcceptLoop 未退出")
	}
}

type retryOnceListener struct {
	err   error
	calls atomic.Int32
}

func (l *retryOnceListener) Accept() (net.Conn, error) {
	if l.calls.Add(1) == 1 {
		return nil, l.err
	}
	return nil, net.ErrClosed
}

func (*retryOnceListener) Close() error   { return nil }
func (*retryOnceListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestAcceptLoopRetriesResourceErrors(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ENOBUFS, syscall.ENOMEM} {
		t.Run(errno.Error(), func(t *testing.T) {
			ln := &retryOnceListener{err: &net.OpError{Op: "accept", Net: "tcp", Err: errno}}
			if err := AcceptLoop(ln, "", "", nil, nil); err != nil {
				t.Fatalf("资源错误后未继续 accept: %v", err)
			}
			if calls := ln.calls.Load(); calls != 2 {
				t.Fatalf("Accept 调用 %d 次，期望 2 次", calls)
			}
		})
	}
}

type permanentTestListener struct {
	err error
}

func (l *permanentTestListener) Accept() (net.Conn, error) { return nil, l.err }
func (*permanentTestListener) Close() error                { return nil }
func (*permanentTestListener) Addr() net.Addr              { return &net.TCPAddr{} }

func TestAcceptLoopReturnsPermanentError(t *testing.T) {
	want := errors.New("permanent accept failure")
	err := AcceptLoop(&permanentTestListener{err: want}, "", "", nil, nil)
	if !errors.Is(err, want) {
		t.Fatalf("err=%v want=%v", err, want)
	}
}

type deadlineSpyConn struct {
	net.Conn
	mu        sync.Mutex
	deadlines []time.Time
}

func (c *deadlineSpyConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, deadline)
	c.mu.Unlock()
	return c.Conn.SetDeadline(deadline)
}

func TestProxyHandshakeDeadlineClearedBeforeRelay(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	spy := &deadlineSpyConn{Conn: server}
	h := func(network, host string, port uint16) (net.Conn, error) {
		up, peer := net.Pipe()
		go func() {
			time.Sleep(100 * time.Millisecond)
			_ = peer.Close()
		}()
		return up, nil
	}
	done := make(chan error, 1)
	go func() { done <- Handle(spy, "", "", h, nil) }()
	if _, err := io.WriteString(client, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	spy.mu.Lock()
	deadlines := append([]time.Time(nil), spy.deadlines...)
	spy.mu.Unlock()
	if len(deadlines) < 2 || deadlines[0].IsZero() || !deadlines[len(deadlines)-1].IsZero() {
		t.Fatalf("握手 deadline 未正确设置并清除: %v", deadlines)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Handle 未退出")
	}
}

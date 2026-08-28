package dialer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func wsLen127(n64 uint64) []byte {
	hdr := []byte{0x82, 127}
	var ext [8]byte
	binary.BigEndian.PutUint64(ext[:], n64)
	return append(hdr, ext[:]...)
}

func TestWSFrameTooLarge(t *testing.T) {
	for _, n64 := range []uint64{maxWSFrame + 1, 1 << 40, ^uint64(0)} {
		c := &wsConn{br: bufio.NewReader(bytes.NewReader(wsLen127(n64)))}
		_, err := c.readFrame()
		if err == nil || !strings.Contains(err.Error(), "too large") {
			t.Fatalf("n=%d err=%v", n64, err)
		}
	}
}

func TestWSFrameBinaryPayload(t *testing.T) {
	c := &wsConn{br: bufio.NewReader(bytes.NewReader([]byte{0x82, 0x05, 'h', 'e', 'l', 'l', 'o'}))}
	got, err := c.readFrame()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q", got)
	}
}

func TestUpgradeWebsocketHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		req, err := http.ReadRequest(br)
		if err != nil {
			errc <- err
			return
		}
		if req.URL.Path != "/ws-tunnel-test" {
			errc <- fmt.Errorf("path %s", req.URL.Path)
			return
		}
		key := req.Header.Get("Sec-WebSocket-Key")
		sum := sha1.Sum([]byte(key + wsGUID))
		accept := base64.StdEncoding.EncodeToString(sum[:])
		_, _ = fmt.Fprintf(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
		_, _ = c.Write([]byte{0x82, 0x05, 'h', 'e', 'l', 'l', 'o'})
		errc <- nil
		time.Sleep(200 * time.Millisecond)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	ws, err := upgradeWebsocket(ctx, raw, Node{Path: "/ws-tunnel-test", SNI: "cover.example"})
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, err := ws.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("payload %q", buf[:n])
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeWebsocketEmptyPath(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_, err := upgradeWebsocket(context.Background(), a, Node{})
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("err %v", err)
	}
}

func TestUpgradeWebsocketRequiresAccept(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_, _ = http.ReadRequest(bufio.NewReader(server))
		_, _ = io.WriteString(server, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := upgradeWebsocket(ctx, client, Node{Path: "/ws", SNI: "cover.example"}); err == nil || !strings.Contains(err.Error(), "accept") {
		t.Fatalf("缺少 Sec-WebSocket-Accept 时应失败: %v", err)
	}
}

type stagedWSConn struct {
	mu      sync.Mutex
	writes  [][]byte
	first   chan struct{}
	second  chan struct{}
	release chan struct{}
}

func (c *stagedWSConn) Read([]byte) (int, error) { return 0, io.EOF }

func (c *stagedWSConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	n := len(c.writes)
	c.mu.Unlock()
	switch n {
	case 1:
		close(c.first)
		<-c.release
	case 2:
		close(c.second)
	}
	return len(p), nil
}

func (*stagedWSConn) Close() error                     { return nil }
func (*stagedWSConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*stagedWSConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*stagedWSConn) SetDeadline(time.Time) error      { return nil }
func (*stagedWSConn) SetReadDeadline(time.Time) error  { return nil }
func (*stagedWSConn) SetWriteDeadline(time.Time) error { return nil }

func TestWebSocketPongDoesNotInterleaveDataFrame(t *testing.T) {
	raw := &stagedWSConn{
		first:   make(chan struct{}),
		second:  make(chan struct{}),
		release: make(chan struct{}),
	}
	ws := newWSConn(raw, bufio.NewReader(bytes.NewReader([]byte{0x89, 0x01, 'p'})))
	writeDone := make(chan error, 1)
	go func() {
		_, err := ws.Write([]byte("data"))
		writeDone <- err
	}()
	select {
	case <-raw.first:
	case <-time.After(time.Second):
		t.Fatal("数据帧未开始写入")
	}

	readStarted := make(chan struct{})
	readDone := make(chan error, 1)
	go func() {
		close(readStarted)
		_, err := ws.readFrame()
		readDone <- err
	}()
	<-readStarted
	interleaved := false
	select {
	case <-raw.second:
		interleaved = true
	case <-time.After(100 * time.Millisecond):
	}
	close(raw.release)
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("数据帧写入未完成")
	}
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Pong 写入未完成")
	}
	if interleaved {
		t.Fatal("Pong 帧插入了数据帧头与负载之间")
	}
	raw.mu.Lock()
	defer raw.mu.Unlock()
	if len(raw.writes) != 4 || raw.writes[0][0]&0x0f != 0x02 || raw.writes[2][0]&0x0f != 0x0a {
		t.Fatalf("WebSocket 帧写入顺序异常: %d", len(raw.writes))
	}
}

type discardWSConn struct{}

func (*discardWSConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (*discardWSConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*discardWSConn) Close() error                     { return nil }
func (*discardWSConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*discardWSConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*discardWSConn) SetDeadline(time.Time) error      { return nil }
func (*discardWSConn) SetReadDeadline(time.Time) error  { return nil }
func (*discardWSConn) SetWriteDeadline(time.Time) error { return nil }

func BenchmarkWebSocketWrite32K(b *testing.B) {
	ws := newWSConn(&discardWSConn{}, bufio.NewReader(bytes.NewReader(nil)))
	payload := make([]byte, 32*1024)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := ws.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
}

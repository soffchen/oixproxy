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

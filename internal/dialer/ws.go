package dialer

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	wsGUID     = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	maxWSFrame = 1 << 20
)

func upgradeWebsocket(ctx context.Context, conn net.Conn, n Node) (net.Conn, error) {
	path := n.Path
	if path == "" {
		return nil, fmt.Errorf("ech-tls websocket path is empty")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	var keyB [16]byte
	if _, err := io.ReadFull(rand.Reader, keyB[:]); err != nil {
		return nil, err
	}
	secKey := base64.StdEncoding.EncodeToString(keyB[:])
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + n.sni() + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: " + secKey + "\r\n" +
		"\r\n"
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
		defer conn.SetDeadline(time.Time{})
	}
	if _, err := io.WriteString(conn, req); err != nil {
		return nil, fmt.Errorf("websocket request: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		return nil, fmt.Errorf("websocket response: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols ||
		!strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		return nil, fmt.Errorf("websocket unexpected status %s", resp.Status)
	}
	accept := resp.Header.Get("Sec-WebSocket-Accept")
	sum := sha1.Sum([]byte(secKey + wsGUID))
	want := base64.StdEncoding.EncodeToString(sum[:])
	if accept != want {
		return nil, fmt.Errorf("websocket accept mismatch")
	}
	return newWSConn(conn, br), nil
}

type wsConn struct {
	net.Conn
	br     *bufio.Reader
	rbuf   []byte
	readM  sync.Mutex
	writeM sync.Mutex
}

func newWSConn(c net.Conn, br *bufio.Reader) *wsConn {
	return &wsConn{Conn: c, br: br}
}

func (c *wsConn) Read(p []byte) (int, error) {
	c.readM.Lock()
	defer c.readM.Unlock()
	for len(c.rbuf) == 0 {
		payload, err := c.readFrame()
		if err != nil {
			return 0, err
		}
		if payload == nil {
			continue
		}
		c.rbuf = payload
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

func (c *wsConn) readFrame() ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return nil, err
	}
	opcode := hdr[0] & 0x0f
	masked := hdr[1]&0x80 != 0
	n := int(hdr[1] & 0x7f)
	switch n {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return nil, err
		}
		n = int(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return nil, err
		}
		n64 := binary.BigEndian.Uint64(ext[:])
		if n64 > maxWSFrame {
			return nil, fmt.Errorf("websocket frame too large")
		}
		n = int(n64)
	}
	if n < 0 || n > maxWSFrame {
		return nil, fmt.Errorf("websocket frame too large")
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(c.br, mask[:]); err != nil {
			return nil, err
		}
	}
	payload := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(c.br, payload); err != nil {
			return nil, err
		}
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	switch opcode {
	case 0x8:
		return nil, io.EOF
	case 0x9:
		if err := c.writeLockedFrame(0xA, payload); err != nil {
			return nil, fmt.Errorf("websocket pong: %w", err)
		}
		return nil, nil
	case 0xA:
		return nil, nil
	case 0x1, 0x2, 0x0:
		return payload, nil
	default:
		return nil, fmt.Errorf("websocket opcode %d", opcode)
	}
}

func (c *wsConn) Write(p []byte) (int, error) {
	if err := c.writeLockedFrame(0x2, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wsConn) writeLockedFrame(opcode byte, payload []byte) error {
	c.writeM.Lock()
	defer c.writeM.Unlock()
	return c.writeFrame(opcode, payload)
}

func (c *wsConn) writeFrame(opcode byte, payload []byte) error {
	n := len(payload)
	var hdr []byte
	hdr = append(hdr, 0x80|opcode)
	switch {
	case n < 126:
		hdr = append(hdr, 0x80|byte(n))
	case n < 65536:
		hdr = append(hdr, 0x80|126, byte(n>>8), byte(n))
	default:
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		hdr = append(hdr, 0x80|127)
		hdr = append(hdr, ext[:]...)
	}
	var mask [4]byte
	if _, err := io.ReadFull(rand.Reader, mask[:]); err != nil {
		return err
	}
	hdr = append(hdr, mask[:]...)
	masked := make([]byte, n)
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	if _, err := c.Conn.Write(hdr); err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	_, err := c.Conn.Write(masked)
	return err
}

func (c *wsConn) Close() error {
	_ = c.writeLockedFrame(0x8, []byte{0x03, 0xe8})
	return c.Conn.Close()
}

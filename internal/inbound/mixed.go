package inbound

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// Handler dials the upstream for a TCP target.
type Handler func(network, host string, port uint16) (net.Conn, error)

// ListenMixed accepts SOCKS5 and HTTP proxy on the same port.
func ListenMixed(addr string, user, pass string, h Handler) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go AcceptLoop(ln, user, pass, h)
	return ln, nil
}

// AcceptLoop serves mixed SOCKS5/HTTP on ln until it is closed.
func AcceptLoop(ln net.Listener, user, pass string, h Handler) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			_ = Handle(c, user, pass, h)
		}()
	}
}

// Handle serves one mixed SOCKS5/HTTP client connection.
func Handle(c net.Conn, user, pass string, h Handler) error {
	return serve(c, user, pass, h)
}

func serve(c net.Conn, user, pass string, h Handler) error {
	br := bufio.NewReader(c)
	b, err := br.Peek(1)
	if err != nil {
		return err
	}
	if b[0] == 0x05 {
		return serveSOCKS(br, c, user, pass, h)
	}
	return serveHTTP(br, c, user, pass, h)
}

func serveSOCKS(br *bufio.Reader, c net.Conn, user, pass string, h Handler) error {
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return err
	}
	nmethod := int(hdr[1])
	methods := make([]byte, nmethod)
	if _, err := io.ReadFull(br, methods); err != nil {
		return err
	}
	needAuth := user != ""
	chosen := byte(0x00)
	if needAuth {
		chosen = 0x02
		ok := false
		for _, m := range methods {
			if m == 0x02 {
				ok = true
				break
			}
		}
		if !ok {
			_, _ = c.Write([]byte{0x05, 0xff})
			return fmt.Errorf("socks auth required")
		}
	}
	if _, err := c.Write([]byte{0x05, chosen}); err != nil {
		return err
	}
	if needAuth {
		var authHdr [2]byte
		if _, err := io.ReadFull(br, authHdr[:]); err != nil {
			return err
		}
		ulen := int(authHdr[1])
		ubuf := make([]byte, ulen)
		if _, err := io.ReadFull(br, ubuf); err != nil {
			return err
		}
		var plen [1]byte
		if _, err := io.ReadFull(br, plen[:]); err != nil {
			return err
		}
		pbuf := make([]byte, int(plen[0]))
		if _, err := io.ReadFull(br, pbuf); err != nil {
			return err
		}
		if string(ubuf) != user || string(pbuf) != pass {
			_, _ = c.Write([]byte{0x01, 0x01})
			return fmt.Errorf("socks auth failed")
		}
		if _, err := c.Write([]byte{0x01, 0x00}); err != nil {
			return err
		}
	}

	var req [4]byte
	if _, err := io.ReadFull(br, req[:]); err != nil {
		return err
	}
	if req[0] != 0x05 || req[1] != 0x01 {
		_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("socks command %d", req[1])
	}
	host, port, err := readSOCKSAddr(br, req[3])
	if err != nil {
		return err
	}
	up, err := h("tcp", host, port)
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return err
	}
	defer up.Close()
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	return relay(c, br, up)
}

func readSOCKSAddr(br *bufio.Reader, atyp byte) (string, uint16, error) {
	var host string
	switch atyp {
	case 0x01:
		var ip [4]byte
		if _, err := io.ReadFull(br, ip[:]); err != nil {
			return "", 0, err
		}
		host = net.IP(ip[:]).String()
	case 0x03:
		l, err := br.ReadByte()
		if err != nil {
			return "", 0, err
		}
		b := make([]byte, int(l))
		if _, err := io.ReadFull(br, b); err != nil {
			return "", 0, err
		}
		host = string(b)
	case 0x04:
		var ip [16]byte
		if _, err := io.ReadFull(br, ip[:]); err != nil {
			return "", 0, err
		}
		host = net.IP(ip[:]).String()
	default:
		return "", 0, fmt.Errorf("socks atyp %d", atyp)
	}
	var p [2]byte
	if _, err := io.ReadFull(br, p[:]); err != nil {
		return "", 0, err
	}
	return host, binary.BigEndian.Uint16(p[:]), nil
}

func serveHTTP(br *bufio.Reader, c net.Conn, user, pass string, h Handler) error {
	req, err := http.ReadRequest(br)
	if err != nil {
		return err
	}
	if user != "" {
		u, p, ok := parseBasic(req.Header.Get("Proxy-Authorization"))
		if !ok || u != user || p != pass {
			_, _ = c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"oixproxy\"\r\nContent-Length: 0\r\n\r\n"))
			return fmt.Errorf("http auth failed")
		}
	}
	if req.Method == http.MethodConnect {
		host, port, err := splitHostPort(req.Host, 443)
		if err != nil {
			return err
		}
		up, err := h("tcp", host, port)
		if err != nil {
			_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
			return err
		}
		defer up.Close()
		if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return err
		}
		return relay(c, br, up)
	}
	host, port, err := splitHostPort(req.URL.Host, 80)
	if err != nil {
		return err
	}
	up, err := h("tcp", host, port)
	if err != nil {
		return err
	}
	defer up.Close()
	req.RequestURI = ""
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	if err := req.Write(up); err != nil {
		return err
	}
	return relay(c, br, up)
}

func splitHostPort(hp string, def uint16) (string, uint16, error) {
	if hp == "" {
		return "", 0, fmt.Errorf("empty host")
	}
	host, ps, err := net.SplitHostPort(hp)
	if err != nil {
		return hp, def, nil
	}
	p, err := strconv.Atoi(ps)
	if err != nil {
		return "", 0, err
	}
	return host, uint16(p), nil
}

func parseBasic(h string) (string, string, bool) {
	const p = "Basic "
	if !strings.HasPrefix(h, p) && !strings.HasPrefix(h, "basic ") {
		return "", "", false
	}
	// std library already decoded? no, still base64. Keep simple: split after decode in caller if needed.
	// Use http's built-in via a dummy request? Skip, decode here.
	return parseBasicB64(strings.TrimSpace(h[len(p):]))
}

func parseBasicB64(s string) (string, string, bool) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", "", false
	}
	u, p, ok := strings.Cut(string(raw), ":")
	return u, p, ok
}

func relay(client net.Conn, br *bufio.Reader, up net.Conn) error {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(up, br)
		closeWrite(up)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, up)
		closeWrite(client)
	}()
	wg.Wait()
	return nil
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
		return
	}
	type closer interface{ CloseWrite() error }
	if cw, ok := c.(closer); ok {
		_ = cw.CloseWrite()
	}
}

package inbound

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Handler dials the upstream for a TCP target.
type Handler func(network, host string, port uint16) (net.Conn, error)

// UDPDialer opens a snell UDP session. Nil means UDP ASSOCIATE is rejected.
type UDPDialer func() (net.PacketConn, error)

const (
	proxyHandshakeTimeout = 30 * time.Second
	retryInitialDelay     = 5 * time.Millisecond
	retryMaxDelay         = time.Second
)

type mixedListener struct {
	net.Listener
	hub *udpHub
}

func (m *mixedListener) Close() error {
	err := m.Listener.Close()
	if m.hub != nil {
		if e := m.hub.Close(); err == nil {
			err = e
		}
	}
	return err
}

func listenerHub(ln net.Listener) *udpHub {
	if m, ok := ln.(*mixedListener); ok {
		return m.hub
	}
	return nil
}

// ListenMixed accepts SOCKS5 and HTTP proxy on the same port.
// When udp is set, SOCKS UDP ASSOCIATE binds the same host:port as TCP.
func ListenMixed(addr string, user, pass string, h Handler, udp UDPDialer) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	ml := &mixedListener{Listener: ln}
	if udp != nil {
		pc, err := listenPacketSame(ln.Addr().String())
		if err != nil {
			_ = ln.Close()
			return nil, err
		}
		ml.hub = newUDPHub(pc)
	}
	go func() {
		if err := AcceptLoop(ml, user, pass, h, udp); err != nil {
			log.Printf("代理监听 %s 已停止: %v", ml.Addr(), err)
			_ = ml.Close()
		}
	}()
	return ml, nil
}

// AcceptLoop serves mixed SOCKS5/HTTP on ln until it is closed.
func AcceptLoop(ln net.Listener, user, pass string, h Handler, udp UDPDialer) error {
	hub := listenerHub(ln)
	var retryDelay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			if !retryableNetworkError(err) {
				return fmt.Errorf("accept: %w", err)
			}
			retryDelay = nextRetryDelay(retryDelay)
			log.Printf("accept: %v，%s 后重试", err, retryDelay)
			time.Sleep(retryDelay)
			continue
		}
		retryDelay = 0
		go func(c net.Conn) {
			defer c.Close()
			if err := serve(c, user, pass, h, udp, hub); err != nil && err != io.EOF && err != net.ErrClosed {
				log.Printf("代理连接 %s: %v", c.RemoteAddr(), err)
			}
		}(c)
	}
}

func retryableNetworkError(err error) bool {
	if errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.ENOMEM) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary())
}

// Handle serves one mixed SOCKS5/HTTP client connection.
func Handle(c net.Conn, user, pass string, h Handler, udp UDPDialer) error {
	return serve(c, user, pass, h, udp, nil)
}

func serve(c net.Conn, user, pass string, h Handler, udp UDPDialer, hub *udpHub) error {
	if err := c.SetDeadline(time.Now().Add(proxyHandshakeTimeout)); err != nil {
		return fmt.Errorf("设置代理握手超时: %w", err)
	}
	br := bufio.NewReader(c)
	b, err := br.Peek(1)
	if err != nil {
		return err
	}
	if b[0] == 0x05 {
		return serveSOCKS(br, c, user, pass, h, udp, hub)
	}
	return serveHTTP(br, c, user, pass, h)
}

func serveSOCKS(br *bufio.Reader, c net.Conn, user, pass string, h Handler, udp UDPDialer, hub *udpHub) error {
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
	wantMethod := byte(0x00)
	if needAuth {
		wantMethod = 0x02
	}
	chosen := byte(0xff)
	for _, m := range methods {
		if m == wantMethod {
			chosen = wantMethod
			break
		}
	}
	if chosen == 0xff {
		_, _ = c.Write([]byte{0x05, 0xff})
		return fmt.Errorf("socks authentication method unavailable")
	}
	if _, err := c.Write([]byte{0x05, chosen}); err != nil {
		return err
	}
	if needAuth {
		var authHdr [2]byte
		if _, err := io.ReadFull(br, authHdr[:]); err != nil {
			return err
		}
		if authHdr[0] != 0x01 {
			_, _ = c.Write([]byte{0x01, 0x01})
			return fmt.Errorf("socks auth version %d", authHdr[0])
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
	if req[0] != 0x05 || req[2] != 0x00 {
		return fmt.Errorf("socks version %d", req[0])
	}
	if req[1] == 0x03 {
		host, port, err := readSOCKSAddr(br, req[3])
		if err != nil {
			return err
		}
		if err := c.SetDeadline(time.Time{}); err != nil {
			return fmt.Errorf("清除代理握手超时: %w", err)
		}
		return serveUDPAssociate(c, br, udp, hub, associateExpect(host, port))
	}
	if req[1] != 0x01 {
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
	if err := c.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("清除代理握手超时: %w", err)
	}
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
		if err := c.SetDeadline(time.Time{}); err != nil {
			return fmt.Errorf("清除代理握手超时: %w", err)
		}
		if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return err
		}
		return relay(c, br, up)
	}
	_, _ = c.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nContent-Length: 0\r\n\r\n"))
	return fmt.Errorf("http method %s", req.Method)
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
	if p < 1 || p > 65535 {
		return "", 0, fmt.Errorf("invalid port %d", p)
	}
	return host, uint16(p), nil
}

func parseBasic(h string) (string, string, bool) {
	scheme, encoded, ok := strings.Cut(strings.TrimSpace(h), " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return "", "", false
	}
	return parseBasicB64(strings.TrimSpace(encoded))
}

func nextRetryDelay(current time.Duration) time.Duration {
	if current <= 0 {
		return retryInitialDelay
	}
	next := current * 2
	if next > retryMaxDelay {
		return retryMaxDelay
	}
	return next
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
	type result struct {
		direction string
		err       error
	}
	results := make(chan result, 2)
	go func() {
		results <- result{direction: "客户端到上游", err: relayCopy(up, br)}
	}()
	go func() {
		results <- result{direction: "上游到客户端", err: relayCopy(client, up)}
	}()
	var errs []error
	for range 2 {
		result := <-results
		if result.err == nil || errors.Is(result.err, net.ErrClosed) {
			continue
		}
		errs = append(errs, fmt.Errorf("%s: %w", result.direction, result.err))
	}
	return errors.Join(errs...)
}

func relayCopy(dst net.Conn, src io.Reader) error {
	_, err := io.Copy(dst, src)
	if closeErr := closeWrite(dst); err == nil {
		err = closeErr
	}
	return err
}

func closeWrite(c net.Conn) error {
	if tc, ok := c.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	type closer interface{ CloseWrite() error }
	if cw, ok := c.(closer); ok {
		return cw.CloseWrite()
	}
	return nil
}

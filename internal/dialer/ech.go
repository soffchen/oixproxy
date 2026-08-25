package dialer

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"

	utls "github.com/metacubex/utls"

	"github.com/soffchen/oixproxy/internal/identity"
	"github.com/soffchen/oixproxy/internal/snell"
)

type Node struct {
	Name            string
	Server          string
	Port            int
	PSK             string
	SNI             string
	ECHConfig       string // base64 ECHConfigList
	ALPN            string
	Path            string
	Fingerprint     string
	IdentityVersion int
	SkipVerify      bool
	Reuse           bool
	TFO             bool
	UDP             bool
	// LegacyFallback retries ALPN http/1.1 + websocket if the first ECH
	// handshake fails. Profile parse defaults omitted to true; explicit
	// false matches FlClash dedicated nodes.
	LegacyFallback bool
	// Preconnect is idle snell transports to keep ready (FlClash obfs-opts, 0–4).
	Preconnect int
	// DNS is nameservers from the dedicated YAML for this hostname.
	DNS []DNSServer
	// DialIP skips DNS when set (tests only).
	DialIP string
}

func (n Node) Addr() string {
	host := n.Server
	if n.DialIP != "" {
		host = n.DialIP
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", n.Port))
}

func (n Node) sni() string {
	if n.SNI != "" {
		return n.SNI
	}
	return n.Server
}

func (n Node) alpn() string {
	if n.ALPN != "" {
		return n.ALPN
	}
	return identity.ALPNSnellECH
}

func (n Node) identityVersion() int {
	if n.IdentityVersion != 0 {
		return n.IdentityVersion
	}
	return 2
}

func (n Node) fingerprint() string {
	if n.Fingerprint != "" {
		return n.Fingerprint
	}
	return "chrome"
}

// Dial opens snell+ech-tls and issues CONNECT (or UDP) to host:port.
//
// Official helper (SnellCore, reversed): uTLS chrome + ECH + ALPN snell-ech/1
// + DLSNID02 TLS exporter. Clash.Meta FlClash: same chrome/ECH, ALPN http/1.1,
// WebSocket on obfs path, DLSNID01. YAML carries both; official ALPN wins,
// websocket is used when the handshake negotiated http/1.1.
func Dial(ctx context.Context, n Node, network, host string, port uint16) (net.Conn, error) {
	raw, exporter, err := dialTransport(ctx, n)
	if err != nil {
		return nil, err
	}
	sc := snell.NewConnIdentity(raw, []byte(n.PSK), exporter, n.identityVersion())
	switch network {
	case "udp", "udp4", "udp6":
		if err := sc.WriteUDP(); err != nil {
			_ = sc.Close()
			return nil, err
		}
	default:
		if err := sc.WriteConnect(host, port, n.Reuse); err != nil {
			_ = sc.Close()
			return nil, err
		}
	}
	return sc, nil
}

func dialTransport(ctx context.Context, n Node) (net.Conn, []byte, error) {
	conn, st, err := handshakeUTLSRaw(ctx, n, []string{n.alpn()}, false)
	if err != nil && n.LegacyFallback && n.Path != "" && n.alpn() != "http/1.1" {
		conn, st, err = handshakeUTLSRaw(ctx, n, []string{"http/1.1"}, true)
	}
	if err != nil {
		return nil, nil, err
	}

	exporter, expErr := exportFromConn(conn, n)
	alpn := st.NegotiatedProtocol
	if n.Path != "" && (alpn == "http/1.1" || alpn == "") {
		ws, wsErr := upgradeWebsocket(ctx, conn, n)
		if wsErr != nil {
			_ = conn.Close()
			return nil, nil, wsErr
		}
		conn = ws
		if n.identityVersion() != 1 && exporter == nil && expErr != nil {
			_ = conn.Close()
			return nil, nil, expErr
		}
		if n.identityVersion() == 1 {
			return conn, nil, nil
		}
		return conn, exporter, nil
	}
	if alpn != "" && alpn != identity.ALPNSnellECH && alpn != "http/1.1" {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("snell ech-tls negotiated ALPN %q", alpn)
	}
	if n.identityVersion() == 1 {
		return conn, nil, nil
	}
	if expErr != nil {
		_ = conn.Close()
		return nil, nil, expErr
	}
	return conn, exporter, nil
}

func needsPrivateDNS(host string) bool {
	h := strings.ToLower(host)
	return h == "cloud-nodes.com" || strings.HasSuffix(h, ".cloud-nodes.com")
}

func dialTCP(ctx context.Context, n Node) (net.Conn, error) {
	d := net.Dialer{Timeout: 15 * time.Second}
	if deadline, ok := ctx.Deadline(); ok {
		d.Deadline = deadline
	}
	dests, err := Destinations(ctx, n)
	if err != nil {
		return nil, err
	}
	if n.TFO {
		return newTFOConn(ctx, dests, d, true), nil
	}
	var last error
	for _, dest := range dests {
		tcp, err := d.DialContext(ctx, "tcp", dest)
		if err == nil {
			tcpKeepAlive(tcp)
			return tcp, nil
		}
		last = fmt.Errorf("dial %s: %w", dest, err)
	}
	if last == nil {
		last = fmt.Errorf("dial %s: no destination", n.Server)
	}
	return nil, last
}

// HandshakeInfo is TLS state after ClientHello. Used by live probes.
type HandshakeInfo struct {
	ALPN    string
	ECH     bool
	Version uint16
}

func handshakeUTLS(ctx context.Context, n Node, nextProtos []string, websocketALPN bool) (net.Conn, HandshakeInfo, error) {
	c, st, err := handshakeUTLSRaw(ctx, n, nextProtos, websocketALPN)
	if err != nil {
		return nil, HandshakeInfo{}, err
	}
	return c, HandshakeInfo{ALPN: st.NegotiatedProtocol, ECH: st.ECHAccepted, Version: st.Version}, nil
}

func handshakeUTLSRaw(ctx context.Context, n Node, nextProtos []string, websocketALPN bool) (net.Conn, utls.ConnectionState, error) {
	tcp, err := dialTCP(ctx, n)
	if err != nil {
		return nil, utls.ConnectionState{}, err
	}
	echList, err := decodeECH(n.ECHConfig)
	if err != nil {
		_ = tcp.Close()
		return nil, utls.ConnectionState{}, err
	}
	hello, err := clientHelloID(n.fingerprint())
	if err != nil {
		_ = tcp.Close()
		return nil, utls.ConnectionState{}, err
	}
	cfg := &utls.Config{
		ServerName:                     n.sni(),
		NextProtos:                     nextProtos,
		InsecureSkipVerify:             n.SkipVerify,
		EncryptedClientHelloConfigList: echList,
		Renegotiation:                  utls.RenegotiateNever,
	}
	uc := utls.UClient(tcp, cfg, hello)
	if websocketALPN {
		if err := forceHTTP11ALPN(uc); err != nil {
			_ = uc.Close()
			return nil, utls.ConnectionState{}, fmt.Errorf("tls websocket alpn: %w", err)
		}
	}
	if err := uc.HandshakeContext(ctx); err != nil {
		_ = uc.Close()
		return nil, utls.ConnectionState{}, fmt.Errorf("tls handshake: %w", err)
	}
	return uc, uc.ConnectionState(), nil
}

func forceHTTP11ALPN(c *utls.UConn) error {
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}
	has := false
	for _, ext := range c.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
			has = true
			break
		}
	}
	if !has {
		c.Extensions = append(c.Extensions, &utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}})
	}
	return c.BuildHandshakeState()
}

func clientHelloID(name string) (utls.ClientHelloID, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "chrome":
		return utls.HelloChrome_Auto, nil
	case "chrome133":
		return utls.HelloChrome_Auto, nil
	case "chrome120":
		return utls.HelloChrome_120, nil
	case "chrome106":
		return utls.HelloChrome_106_Shuffle, nil
	case "ios":
		return utls.HelloIOS_Auto, nil
	case "safari":
		return utls.HelloSafari_Auto, nil
	case "firefox":
		return utls.HelloFirefox_Auto, nil
	default:
		return utls.ClientHelloID{}, fmt.Errorf("unknown client fingerprint %q", name)
	}
}

func decodeECH(b64 string) ([]byte, error) {
	if b64 == "" {
		return nil, fmt.Errorf("missing ech-config")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(b64))
	}
	if err != nil {
		return nil, fmt.Errorf("ech-config: %w", err)
	}
	if len(raw) < 4 {
		return nil, fmt.Errorf("ech-config too short")
	}
	return raw, nil
}

package dialer

import (
	"context"
	"fmt"
	"net"

	"github.com/soffchen/oixproxy/internal/snell"
)

// ListenPacket opens a snell v4 UDP session for the node.
func ListenPacket(ctx context.Context, n Node) (net.PacketConn, error) {
	if !n.UDP {
		return nil, fmt.Errorf("udp disabled for %s", n.Name)
	}
	raw, exporter, err := dialTransport(ctx, n)
	if err != nil {
		return nil, err
	}
	sc := snell.NewConnIdentity(raw, []byte(n.PSK), exporter, n.identityVersion())
	if err := sc.WriteUDP(); err != nil {
		_ = sc.Close()
		return nil, err
	}
	if err := sc.ReadReply(); err != nil {
		_ = sc.Close()
		return nil, err
	}
	return snell.NewPacketConn(sc), nil
}

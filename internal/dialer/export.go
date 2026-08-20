package dialer

import (
	"context"
	"net"
)

// HandshakeForTest runs a uTLS+ECH handshake. Exported for live tests.
func HandshakeForTest(ctx context.Context, n Node, nextProtos []string, websocketALPN bool) (net.Conn, HandshakeInfo, error) {
	return handshakeUTLS(ctx, n, nextProtos, websocketALPN)
}

// UpgradeWebsocketForTest performs the Clash.Meta websocket upgrade.
func UpgradeWebsocketForTest(ctx context.Context, conn net.Conn, n Node) (net.Conn, error) {
	return upgradeWebsocket(ctx, conn, n)
}

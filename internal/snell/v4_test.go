package snell

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestZeroChunkSetsPeerClosed(t *testing.T) {
	client, peer := pipeConns(t)
	go func() {
		_, _ = client.Write([]byte("hi"))
	}()
	if err := peer.initReader(); err != nil {
		t.Fatal(err)
	}
	payload, err := peer.r.readFrame()
	if err != nil || string(payload) != "hi" {
		t.Fatalf("client frame %q %v", payload, err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := peer.Write([]byte{cmdTunnel})
		if err != nil {
			errCh <- err
			return
		}
		_, err = peer.Write([]byte("ok"))
		if err != nil {
			errCh <- err
			return
		}
		errCh <- peer.HalfClose()
	}()

	buf := make([]byte, 8)
	n, err := client.Read(buf)
	if err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("read %q %v", buf[:n], err)
	}
	n, err = client.Read(buf)
	if n != 0 || err != io.EOF {
		t.Fatalf("zero chunk n=%d err=%v", n, err)
	}
	if !client.PeerClosed() {
		t.Fatal("zero chunk should set PeerClosed")
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("peer write hung")
	}
}

func TestReadReplySkipsLeftoverZeroChunk(t *testing.T) {
	client, peer := pipeConns(t)
	go func() {
		if _, err := peer.Write([]byte{cmdTunnel}); err != nil {
			return
		}
		if _, err := peer.Write([]byte("ok")); err != nil {
			return
		}
		if err := peer.HalfClose(); err != nil {
			return
		}
		if _, err := peer.Write([]byte{cmdTunnel}); err != nil {
			return
		}
		_, _ = peer.Write([]byte("re"))
	}()
	buf := make([]byte, 8)
	n, err := client.Read(buf)
	if err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("read %q %v", buf[:n], err)
	}
	client.ResetReply()
	if err := client.ReadReply(); err != nil {
		t.Fatal(err)
	}
	n, err = client.Read(buf)
	if err != nil || string(buf[:n]) != "re" {
		t.Fatalf("second %q %v", buf[:n], err)
	}
}

func readWarmupRequest(peer *Conn) error {
	if peer.r == nil {
		if err := peer.initReader(); err != nil {
			return err
		}
	}
	if _, err := peer.r.readFrame(); err != nil {
		return err
	}
	if _, err := peer.r.readFrame(); err != nil {
		return err
	}
	return nil
}

func TestWarmupCompletesOnTunnelReply(t *testing.T) {
	client, peer := pipeConns(t)
	errc := make(chan error, 1)
	go func() {
		if err := readWarmupRequest(peer); err != nil {
			errc <- err
			return
		}
		if _, err := peer.Write([]byte{cmdTunnel}); err != nil {
			errc <- err
			return
		}
		if _, err := peer.r.readFrame(); err != nil && err != ErrZeroChunk {
			errc <- err
			return
		}
		errc <- peer.HalfClose()
	}()
	if err := client.Warmup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.PeerClosed() {
		t.Fatal("successful warmup must ResetReply")
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("peer hung")
	}
}

func TestWarmupRejectsDrainTimeout(t *testing.T) {
	client, peer := pipeConns(t)
	go func() {
		if err := readWarmupRequest(peer); err != nil {
			return
		}
		if _, err := peer.Write([]byte{cmdTunnel}); err != nil {
			return
		}
		_, _ = peer.r.readFrame() // client HalfClose
	}()
	ctx, cancel := context.WithTimeout(context.Background(), warmupDrainTimeout+time.Second)
	defer cancel()
	err := client.Warmup(ctx)
	if err == nil {
		t.Fatal("expected drain timeout")
	}
	if client.PeerClosed() {
		t.Fatal("timeout must not set PeerClosed")
	}
}

func TestWarmupRejectsTLSDrop(t *testing.T) {
	client, peer := pipeConns(t)
	raw := peer.Conn
	go func() {
		if err := readWarmupRequest(peer); err != nil {
			return
		}
		if _, err := peer.Write([]byte{cmdTunnel}); err != nil {
			return
		}
		if _, err := peer.r.readFrame(); err != nil && err != ErrZeroChunk {
			return
		}
		_ = raw.Close()
	}()
	err := client.Warmup(context.Background())
	if err == nil {
		t.Fatal("expected drain error")
	}
	if client.PeerClosed() {
		t.Fatal("TLS drop must not set PeerClosed")
	}
	if errors.Is(err, ErrZeroChunk) {
		t.Fatalf("zero-chunk: %v", err)
	}
}

func TestTLSClientHelloNotEmpty(t *testing.T) {
	hello, err := tlsClientHello(warmupHost)
	if err != nil {
		t.Fatal(err)
	}
	if len(hello) < 40 || hello[0] != 22 {
		t.Fatalf("not a TLS handshake record: len=%d first=%d", len(hello), hello[0])
	}
}

func TestTLSDropDoesNotSetPeerClosed(t *testing.T) {
	client, peer := pipeConns(t)
	raw := peer.Conn
	go func() {
		_, _ = peer.Write([]byte{cmdTunnel})
		_, _ = peer.Write([]byte("ok"))
		_ = raw.Close()
	}()
	buf := make([]byte, 8)
	n, err := client.Read(buf)
	if err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("read %q %v", buf[:n], err)
	}
	n, err = client.Read(buf)
	if n != 0 || err == nil {
		t.Fatalf("drop n=%d err=%v", n, err)
	}
	if client.PeerClosed() {
		t.Fatal("TLS drop must not set PeerClosed")
	}
}

func pipeConns(t *testing.T) (client, peer *Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	deadline := time.Now().Add(5 * time.Second)
	_ = a.SetDeadline(deadline)
	_ = b.SetDeadline(deadline)
	psk := []byte("test-psk")
	return NewConnIdentity(a, psk, nil, 2), NewConnIdentity(b, psk, nil, 2)
}

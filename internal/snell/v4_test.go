package snell

import (
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

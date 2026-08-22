package dialer

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soffchen/oixproxy/internal/identity"
	"github.com/soffchen/oixproxy/internal/snell"
)

func TestPoolWarmTakesIdle(t *testing.T) {
	var n atomic.Int32
	p := NewPool(Node{Name: "hk", Reuse: true, Preconnect: 2})
	p.factory = func(ctx context.Context) (*snell.Conn, error) {
		n.Add(1)
		a, b := net.Pipe()
		go func() {
			_, _ = io.Copy(io.Discard, b)
			_ = b.Close()
		}()
		return snell.NewConnIdentity(a, []byte("psk"), make([]byte, identity.ExporterSize), 2), nil
	}
	p.Warm(2)
	deadline := time.Now().Add(2 * time.Second)
	for p.idleCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if p.idleCount() != 2 || n.Load() != 2 {
		t.Fatalf("idle %d factory %d", p.idleCount(), n.Load())
	}
	c, err := p.take(context.Background())
	if err != nil || c == nil {
		t.Fatalf("take: %v", err)
	}
	if n.Load() != 2 {
		t.Fatalf("factory after take %d", n.Load())
	}
	if p.idleCount() != 1 {
		t.Fatalf("idle after take %d", p.idleCount())
	}
	p.Close()
}

func TestPoolTakeWaitsForWarm(t *testing.T) {
	var n atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	p := NewPool(Node{Name: "hk", Reuse: true, Preconnect: 1})
	p.factory = func(ctx context.Context) (*snell.Conn, error) {
		n.Add(1)
		select {
		case <-started:
		default:
			close(started)
		}
		<-release
		a, b := net.Pipe()
		go func() {
			_, _ = io.Copy(io.Discard, b)
			_ = b.Close()
		}()
		return snell.NewConnIdentity(a, []byte("psk"), make([]byte, identity.ExporterSize), 2), nil
	}
	p.Warm(1)
	<-started
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(release)
	}()
	c, err := p.take(context.Background())
	if err != nil || c == nil {
		t.Fatalf("take: %v", err)
	}
	if n.Load() != 1 {
		t.Fatalf("factory %d, want warm conn", n.Load())
	}
	p.Close()
}

func TestPoolTakeCancelDoesNotStartFactory(t *testing.T) {
	var n atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	p := NewPool(Node{Name: "hk", Reuse: true, Preconnect: 1})
	p.factory = func(ctx context.Context) (*snell.Conn, error) {
		n.Add(1)
		select {
		case <-started:
		default:
			close(started)
		}
		<-release
		a, b := net.Pipe()
		go func() {
			_, _ = io.Copy(io.Discard, b)
			_ = b.Close()
		}()
		return snell.NewConnIdentity(a, []byte("psk"), make([]byte, identity.ExporterSize), 2), nil
	}
	p.Warm(1)
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := p.take(ctx)
		errc <- err
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("take %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("take hung after cancel")
	}
	if n.Load() != 1 {
		t.Fatalf("cancelled take started factory %d", n.Load())
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for p.idleCount() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if p.idleCount() != 1 {
		t.Fatalf("warm idle %d", p.idleCount())
	}
	p.Close()
}

func TestPoolPutsOnlyAfterZeroChunk(t *testing.T) {
	t.Run("zero-chunk", func(t *testing.T) {
		idle, d := pooledRoundTrip(t, true)
		if idle != 1 {
			t.Fatalf("idle %d, want put", idle)
		}
		if d > time.Second {
			t.Fatalf("close drained %s", d)
		}
	})
	t.Run("tls-drop", func(t *testing.T) {
		idle, d := pooledRoundTrip(t, false)
		if idle != 0 {
			t.Fatalf("idle %d, want drop", idle)
		}
		if d > time.Second {
			t.Fatalf("close drained %s", d)
		}
	})
}

func pooledRoundTrip(t *testing.T, zeroChunk bool) (idle int, closeDur time.Duration) {
	t.Helper()
	a, b := net.Pipe()
	stop := make(chan struct{})
	t.Cleanup(func() {
		close(stop)
		_ = a.Close()
		_ = b.Close()
	})
	psk := []byte("test-psk")

	p := NewPool(Node{Name: "hk", Reuse: true})
	p.factory = func(ctx context.Context) (*snell.Conn, error) {
		go func() { _, _ = io.Copy(io.Discard, b) }()
		go func() {
			peer := snell.NewConnIdentity(b, psk, nil, 2)
			if _, err := peer.Write([]byte{0}); err != nil {
				return
			}
			if _, err := peer.Write([]byte("ok")); err != nil {
				return
			}
			if zeroChunk {
				_ = peer.HalfClose()
			}
			<-stop
		}()
		return snell.NewConnIdentity(a, psk, nil, 2), nil
	}

	pc, err := p.Dial(context.Background(), Node{Name: "hk", Reuse: true}, "tcp", "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, err := pc.Read(buf)
	if err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("read %q %v", buf[:n], err)
	}
	if zeroChunk {
		n, err = pc.Read(buf)
		if n != 0 || err != io.EOF {
			t.Fatalf("eof n=%d err=%v", n, err)
		}
	}
	start := time.Now()
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	return p.idleCount(), time.Since(start)
}

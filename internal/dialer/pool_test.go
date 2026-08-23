package dialer

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
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

func TestPoolPutWakesOneWaiter(t *testing.T) {
	var n atomic.Int32
	var mu sync.Mutex
	var gates []chan struct{}
	started := make(chan struct{}, 8)
	p := NewPool(Node{Name: "hk", Reuse: true, Preconnect: 2})
	p.factory = func(ctx context.Context) (*snell.Conn, error) {
		n.Add(1)
		gate := make(chan struct{})
		mu.Lock()
		gates = append(gates, gate)
		mu.Unlock()
		started <- struct{}{}
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		a, b := net.Pipe()
		go func() {
			_, _ = io.Copy(io.Discard, b)
			_ = b.Close()
		}()
		return snell.NewConnIdentity(a, []byte("psk"), make([]byte, identity.ExporterSize), 2), nil
	}
	p.Warm(2)
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("warm factory")
		}
	}
	errc := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			c, err := p.take(context.Background())
			if c != nil {
				_ = c.Close()
			}
			errc <- err
		}()
	}
	deadline := time.Now().Add(2 * time.Second)
	for p.waiterCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if p.waiterCount() != 2 {
		t.Fatalf("waiters %d", p.waiterCount())
	}
	mu.Lock()
	close(gates[0])
	mu.Unlock()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first take")
	}
	if n.Load() != 2 {
		t.Fatalf("extra factory after first put %d", n.Load())
	}
	deadline = time.Now().Add(time.Second)
	for p.waiterCount() != 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if p.waiterCount() != 1 {
		t.Fatalf("waiters after one put %d", p.waiterCount())
	}
	mu.Lock()
	close(gates[1])
	mu.Unlock()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second take")
	}
	if n.Load() != 2 {
		t.Fatalf("factory %d", n.Load())
	}
	p.Close()
}

func TestPoolCancelTransfersWakeup(t *testing.T) {
	dummy := func() *snell.Conn {
		a, b := net.Pipe()
		go func() {
			_, _ = io.Copy(io.Discard, b)
			_ = b.Close()
		}()
		return snell.NewConnIdentity(a, []byte("psk"), make([]byte, identity.ExporterSize), 2)
	}
	p := NewPool(Node{Name: "hk", Reuse: true, Preconnect: 2})
	p.warming = 2
	chA := make(chan struct{})
	chB := make(chan struct{})
	p.waiters = []chan struct{}{chA, chB}
	p.idle = []idleConn{{c: dummy(), used: time.Now()}}
	p.notifyOneWaiterLocked()
	select {
	case <-chA:
	default:
		t.Fatal("put should close first waiter")
	}
	p.removeWaiter(chA)
	select {
	case <-chB:
	default:
		t.Fatal("cancel after put must wake the next waiter")
	}
	chC := make(chan struct{})
	p.waiters = []chan struct{}{chC}
	p.wakeOneIfIdle()
	select {
	case <-chC:
	default:
		t.Fatal("cancelled notified waiter must hand idle to the next")
	}
	if p.waiterCount() != 0 {
		t.Fatalf("waiters %d", p.waiterCount())
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

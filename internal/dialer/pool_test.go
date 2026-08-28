package dialer

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soffchen/oixproxy/internal/snell"
)

func newTestPool(n Node) *Pool {
	return NewPool(n)
}

func testSnellConn() *snell.Conn {
	a, b := net.Pipe()
	go func() {
		_, _ = io.Copy(io.Discard, b)
		_ = b.Close()
	}()
	return snell.NewConnIdentity(a, []byte("test-psk"), nil, 2)
}

func waitIdle(t *testing.T, p *Pool, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for p.idleCount() != want && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := p.idleCount(); got != want {
		t.Fatalf("空闲连接数为 %d，期望 %d", got, want)
	}
}

func TestPoolWarmBuildsSequentialConnections(t *testing.T) {
	p := newTestPool(Node{Name: "hk", Reuse: true})
	t.Cleanup(p.Close)
	started := make(chan int, 2)
	release := make(chan struct{}, 2)
	var calls atomic.Int32
	var active atomic.Int32
	var maxActive atomic.Int32
	p.factory = func(context.Context) (*snell.Conn, error) {
		id := int(calls.Add(1))
		current := active.Add(1)
		for {
			maximum := maxActive.Load()
			if current <= maximum || maxActive.CompareAndSwap(maximum, current) {
				break
			}
		}
		started <- id
		<-release
		active.Add(-1)
		return testSnellConn(), nil
	}

	p.Warm(2)
	if id := <-started; id != 1 {
		t.Fatalf("首个预连接编号为 %d", id)
	}
	select {
	case id := <-started:
		t.Fatalf("预连接并行启动了第 %d 条", id)
	case <-time.After(50 * time.Millisecond):
	}
	release <- struct{}{}
	if id := <-started; id != 2 {
		t.Fatalf("第二个预连接编号为 %d", id)
	}
	release <- struct{}{}
	waitIdle(t, p, 2)
	if maxActive.Load() != 1 {
		t.Fatalf("并发预连接数为 %d", maxActive.Load())
	}
}

func TestPoolTakeDoesNotWaitForWarm(t *testing.T) {
	p := newTestPool(Node{Name: "hk", Reuse: true})
	t.Cleanup(p.Close)
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	p.factory = func(ctx context.Context) (*snell.Conn, error) {
		if calls.Add(1) == 1 {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return testSnellConn(), nil
	}

	p.Warm(1)
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	c, uses, err := p.take(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 300*time.Millisecond {
		t.Fatalf("前台取连接等待了预热：%s", time.Since(start))
	}
	if uses != 1 || calls.Load() != 2 {
		t.Fatalf("使用次数为 %d，建连次数为 %d", uses, calls.Load())
	}
	_ = c.Close()
	close(release)
}

func TestPoolWarmDoesNotConsumeReuseCount(t *testing.T) {
	p := newTestPool(Node{Name: "hk", Reuse: true})
	t.Cleanup(p.Close)
	p.factory = func(context.Context) (*snell.Conn, error) {
		return testSnellConn(), nil
	}
	p.Warm(1)
	waitIdle(t, p, 1)
	c, uses, err := p.take(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if uses != 1 {
		t.Fatalf("预热后的首次 CONNECT 计数为 %d", uses)
	}
	if !p.put(c, uses) {
		t.Fatal("首次 CONNECT 后应能回池")
	}
	c, uses, err = p.take(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if uses != poolMaxUses {
		t.Fatalf("第二次 CONNECT 计数为 %d", uses)
	}
	if p.put(c, uses) {
		t.Fatal("达到复用上限后仍然回池")
	}
	_ = c.Close()
}

func TestPoolUsesFIFO(t *testing.T) {
	p := newTestPool(Node{Name: "hk", Reuse: true})
	t.Cleanup(p.Close)
	first := testSnellConn()
	second := testSnellConn()
	if !p.put(first, 0) || !p.put(second, 0) {
		t.Fatal("写入测试连接失败")
	}
	got, _, ok := p.pop()
	if !ok || got != first {
		t.Fatal("连接池没有先取最早进入的连接")
	}
	_ = got.Close()
}

func TestPoolCloseRejectsNewConnections(t *testing.T) {
	p := newTestPool(Node{Name: "hk", Reuse: true})
	var calls atomic.Int32
	p.factory = func(context.Context) (*snell.Conn, error) {
		calls.Add(1)
		return testSnellConn(), nil
	}
	p.Close()
	_, _, err := p.take(context.Background())
	if !errors.Is(err, errPoolClosed) {
		t.Fatalf("关闭后的错误为 %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("关闭后仍建立了 %d 条连接", calls.Load())
	}
}

func TestPoolPutsOnlyAfterPeerZeroChunk(t *testing.T) {
	t.Run("服务端零块", func(t *testing.T) {
		idle, d := pooledRoundTrip(t, true)
		if idle != 1 {
			t.Fatalf("空闲连接数为 %d", idle)
		}
		if d > time.Second {
			t.Fatalf("关闭耗时 %s", d)
		}
	})
	t.Run("TLS 断开", func(t *testing.T) {
		idle, d := pooledRoundTrip(t, false)
		if idle != 0 {
			t.Fatalf("空闲连接数为 %d", idle)
		}
		if d > time.Second {
			t.Fatalf("关闭耗时 %s", d)
		}
	})
	t.Run("未收到服务端零块", func(t *testing.T) {
		idle, d := pooledRoundTripWithoutPeerClose(t)
		if idle != 0 {
			t.Fatalf("空闲连接数为 %d", idle)
		}
		if d > 200*time.Millisecond {
			t.Fatalf("关闭仍在等待排空：%s", d)
		}
	})
}

func pooledRoundTripWithoutPeerClose(t *testing.T) (int, time.Duration) {
	t.Helper()
	a, b := net.Pipe()
	stop := make(chan struct{})
	t.Cleanup(func() {
		close(stop)
		_ = a.Close()
		_ = b.Close()
	})
	psk := []byte("test-psk")
	p := newTestPool(Node{Name: "hk", Reuse: true})
	p.factory = func(context.Context) (*snell.Conn, error) {
		go func() { _, _ = io.Copy(io.Discard, b) }()
		go func() {
			peer := snell.NewConnIdentity(b, psk, nil, 2)
			_, _ = peer.Write([]byte{0})
			_, _ = peer.Write([]byte("ok"))
			<-stop
		}()
		return snell.NewConnIdentity(a, psk, nil, 2), nil
	}
	pc, err := p.Dial(context.Background(), p.node, "tcp", "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, err := pc.Read(buf)
	if err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("读取 %q：%v", buf[:n], err)
	}
	start := time.Now()
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	return p.idleCount(), time.Since(start)
}

func pooledRoundTrip(t *testing.T, zeroChunk bool) (int, time.Duration) {
	t.Helper()
	a, b := net.Pipe()
	stop := make(chan struct{})
	t.Cleanup(func() {
		close(stop)
		_ = a.Close()
		_ = b.Close()
	})
	psk := []byte("test-psk")
	p := newTestPool(Node{Name: "hk", Reuse: true})
	dropped := make(chan struct{})
	p.factory = func(context.Context) (*snell.Conn, error) {
		go func() { _, _ = io.Copy(io.Discard, b) }()
		go func() {
			peer := snell.NewConnIdentity(b, psk, nil, 2)
			_, _ = peer.Write([]byte{0})
			_, _ = peer.Write([]byte("ok"))
			if zeroChunk {
				_ = peer.HalfClose()
			} else {
				_ = b.Close()
				close(dropped)
			}
			<-stop
		}()
		return snell.NewConnIdentity(a, psk, nil, 2), nil
	}
	pc, err := p.Dial(context.Background(), p.node, "tcp", "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, err := pc.Read(buf)
	if err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("读取 %q：%v", buf[:n], err)
	}
	if zeroChunk {
		n, err = pc.Read(buf)
		if n != 0 || err != io.EOF {
			t.Fatalf("结束读取 n=%d err=%v", n, err)
		}
	} else {
		<-dropped
	}
	start := time.Now()
	err = pc.Close()
	if zeroChunk && err != nil {
		t.Fatal(err)
	}
	return p.idleCount(), time.Since(start)
}

func TestPoolDialDoesNotWaitForConnectReply(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	psk := []byte("test-psk")
	connectSeen := make(chan struct{})
	p := newTestPool(Node{Name: "hk", Reuse: false})
	p.factory = func(context.Context) (*snell.Conn, error) {
		go func() {
			buf := make([]byte, 8192)
			if _, err := b.Read(buf); err != nil {
				return
			}
			close(connectSeen)
			if _, err := b.Read(buf); err != nil {
				return
			}
			peer := snell.NewConnIdentity(b, psk, nil, 2)
			_, _ = peer.Write([]byte{0})
			_, _ = peer.Write([]byte("ok"))
		}()
		return snell.NewConnIdentity(a, psk, nil, 2), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	pc, err := p.Dial(ctx, p.node, "tcp", "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if time.Since(start) > 300*time.Millisecond {
		t.Fatalf("Dial 等待了 CONNECT 回复：%s", time.Since(start))
	}
	select {
	case <-connectSeen:
	case <-time.After(time.Second):
		t.Fatal("服务端没有收到 CONNECT")
	}
	if _, err := pc.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	n, err := pc.Read(buf)
	if err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("读取 %q：%v", buf[:n], err)
	}
}

func TestPoolDialRetriesFailedHeaderWrite(t *testing.T) {
	var calls atomic.Int32
	psk := []byte("test-psk")
	p := newTestPool(Node{Name: "hk", Reuse: true})
	p.factory = func(context.Context) (*snell.Conn, error) {
		a, b := net.Pipe()
		if calls.Add(1) == 1 {
			_ = b.Close()
			return snell.NewConnIdentity(a, psk, nil, 2), nil
		}
		go func() { _, _ = io.Copy(io.Discard, b) }()
		go func() {
			peer := snell.NewConnIdentity(b, psk, nil, 2)
			_, _ = peer.Write([]byte{0})
			_, _ = peer.Write([]byte("ok"))
		}()
		return snell.NewConnIdentity(a, psk, nil, 2), nil
	}
	pc, err := p.Dial(context.Background(), p.node, "tcp", "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if calls.Load() != 2 {
		t.Fatalf("建连次数为 %d", calls.Load())
	}
	buf := make([]byte, 8)
	n, err := pc.Read(buf)
	if err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("读取 %q：%v", buf[:n], err)
	}
}

func TestPoolPutRejectsMaxUses(t *testing.T) {
	p := newTestPool(Node{Name: "hk", Reuse: true})
	t.Cleanup(p.Close)
	c := testSnellConn()
	if p.put(c, poolMaxUses) {
		t.Fatal("达到复用上限后仍然回池")
	}
	_ = c.Close()
	if p.idleCount() != 0 {
		t.Fatalf("空闲连接数为 %d", p.idleCount())
	}
}

func TestPoolCloseAtMaxUsesClosesTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peerRaw := <-accepted
	if peerRaw == nil {
		t.Fatal("服务端未接受连接")
	}
	t.Cleanup(func() { _ = peerRaw.Close() })
	psk := []byte("test-psk")
	pc := &pooledConn{
		Conn: snell.NewConnIdentity(raw, psk, nil, 2),
		pool: newTestPool(Node{Name: "hk", Reuse: true}),
		uses: poolMaxUses,
	}
	pc.MarkReusable()
	peer := snell.NewConnIdentity(peerRaw, psk, nil, 2)
	writeDone := make(chan error, 1)
	go func() {
		if _, err := peer.Write([]byte{0}); err != nil {
			writeDone <- err
			return
		}
		writeDone <- peer.HalfClose()
	}()
	buf := make([]byte, 8)
	if _, err := pc.Read(buf); err != io.EOF {
		t.Fatalf("服务端零块错误为 %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	if pc.pool.idleCount() != 0 {
		t.Fatalf("达到复用上限后仍有 %d 条空闲连接", pc.pool.idleCount())
	}
	if err := peerRaw.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for {
		_, err := peerRaw.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("等待 TCP FIN：%v", err)
		}
	}
}

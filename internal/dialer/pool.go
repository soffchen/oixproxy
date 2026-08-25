package dialer

import (
	"context"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/soffchen/oixproxy/internal/snell"
)

const (
	poolMaxIdle = 10
	poolIdleAge = 15 * time.Second
)

type idleConn struct {
	c    *snell.Conn
	used time.Time
}

// Pool keeps ready snell+ech-tls transports, matching FlClash reuse + preconnect.
type Pool struct {
	node    Node
	factory func(context.Context) (*snell.Conn, error)
	probe   func(context.Context, *snell.Conn) error

	mu         sync.Mutex
	idle       []idleConn
	closed     bool
	warming    int
	bypassWarm bool
	waiters    []chan struct{}
}

func NewPool(n Node) *Pool {
	p := &Pool{node: n}
	p.factory = func(ctx context.Context) (*snell.Conn, error) {
		raw, exporter, err := dialTransport(ctx, n)
		if err != nil {
			return nil, err
		}
		return snell.NewConnIdentity(raw, []byte(n.PSK), exporter, n.identityVersion()), nil
	}
	if n.Reuse {
		p.probe = func(ctx context.Context, c *snell.Conn) error {
			return c.Warmup(ctx)
		}
	}
	return p
}

func (p *Pool) finishWarm() {
	p.mu.Lock()
	p.warming--
	if p.warming < 0 {
		p.warming = 0
	}
	if p.warming == 0 {
		p.notifyWaitersLocked()
	}
	p.mu.Unlock()
}

func (p *Pool) releaseWarmWaiters() {
	p.mu.Lock()
	p.warming--
	if p.warming < 0 {
		p.warming = 0
	}
	p.bypassWarm = true
	p.notifyWaitersLocked()
	p.mu.Unlock()
}

func (p *Pool) Warm(n int) {
	if n <= 0 {
		return
	}
	p.mu.Lock()
	p.warming += n
	p.mu.Unlock()
	for i := 0; i < n; i++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			c, err := p.factory(ctx)
			if err != nil {
				p.finishWarm()
				log.Printf("preconnect %s: %v", p.node.Name, err)
				return
			}
			if p.probe != nil {
				p.releaseWarmWaiters()
				if err := p.probe(ctx, c); err != nil {
					log.Printf("preconnect warmup %s: %v", p.node.Name, err)
					_ = c.Close()
					return
				}
				if !p.put(c) {
					_ = c.Close()
				}
				return
			}
			if !p.put(c) {
				_ = c.Close()
			}
			p.finishWarm()
		}()
	}
}

func (p *Pool) Dial(ctx context.Context, n Node, network, host string, port uint16) (net.Conn, error) {
	switch network {
	case "udp", "udp4", "udp6":
		return Dial(ctx, n, network, host, port)
	}
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		sc, err := p.take(ctx)
		if err != nil {
			return nil, err
		}
		if dl, ok := ctx.Deadline(); ok {
			_ = sc.SetDeadline(dl)
		} else {
			_ = sc.SetDeadline(time.Now().Add(20 * time.Second))
		}
		if err := sc.WriteConnect(host, port, n.Reuse); err != nil {
			_ = sc.Close()
			last = err
			continue
		}
		_ = sc.SetDeadline(time.Time{})
		pc := &pooledConn{Conn: sc, pool: p}
		if n.Reuse {
			pc.MarkReusable()
		}
		return pc, nil
	}
	return nil, last
}

func (p *Pool) Close() {
	p.mu.Lock()
	p.closed = true
	idle := p.idle
	p.idle = nil
	p.notifyWaitersLocked()
	p.mu.Unlock()
	for _, it := range idle {
		_ = it.c.Close()
	}
}

func (p *Pool) take(ctx context.Context) (*snell.Conn, error) {
	for {
		if c := p.pop(); c != nil {
			return c, nil
		}
		ch, done := p.enqueueWaiter()
		if done {
			break
		}
		if ch == nil {
			continue
		}
		select {
		case <-ch:
			if err := ctx.Err(); err != nil {
				p.wakeOneIfIdle()
				return nil, err
			}
		case <-ctx.Done():
			p.removeWaiter(ch)
			return nil, ctx.Err()
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return p.factory(ctx)
}

func (p *Pool) enqueueWaiter() (ch chan struct{}, done bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.idle) > 0 {
		return nil, false
	}
	if p.closed || p.warming <= 0 || p.bypassWarm {
		return nil, true
	}
	ch = make(chan struct{})
	p.waiters = append(p.waiters, ch)
	return ch, false
}

func (p *Pool) removeWaiter(ch chan struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	found := false
	for _, w := range p.waiters {
		if w != ch {
			p.waiters[n] = w
			n++
		} else {
			found = true
		}
	}
	p.waiters = p.waiters[:n]
	if !found {
		p.notifyOneIfIdleLocked()
	}
}

func (p *Pool) wakeOneIfIdle() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.notifyOneIfIdleLocked()
}

func (p *Pool) notifyOneIfIdleLocked() {
	if len(p.idle) > 0 {
		p.notifyOneWaiterLocked()
	}
}

func (p *Pool) notifyOneWaiterLocked() {
	if len(p.waiters) == 0 {
		return
	}
	ch := p.waiters[0]
	p.waiters = p.waiters[1:]
	close(ch)
}

func (p *Pool) notifyWaitersLocked() {
	for _, ch := range p.waiters {
		close(ch)
	}
	p.waiters = nil
}

func (p *Pool) pop() *snell.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for len(p.idle) > 0 {
		last := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]
		if now.Sub(last.used) > poolIdleAge {
			_ = last.c.Close()
			continue
		}
		return last.c
	}
	return nil
}

func (p *Pool) put(c *snell.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || len(p.idle) >= poolMaxIdle {
		return false
	}
	p.idle = append(p.idle, idleConn{c: c, used: time.Now()})
	p.notifyOneWaiterLocked()
	return true
}

func (p *Pool) waiterCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.waiters)
}

func (p *Pool) idleCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.idle)
}

func (p *Pool) warmingCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.warming
}

const (
	poolConnNew int32 = iota
	poolConnReusable
	poolConnClosed
)

type pooledConn struct {
	*snell.Conn
	pool               *Pool
	closeWriteOnce     sync.Once
	closeWriteReusable bool
	closeWriteErr      error
	once               sync.Once
	closeErr           error
	reusableState      atomic.Int32
}

// MarkReusable allows Close to return this stream to the pool after CONNECT-V2.
func (c *pooledConn) MarkReusable() {
	c.reusableState.CompareAndSwap(poolConnNew, poolConnReusable)
}

func (c *pooledConn) CloseWrite() error {
	_, err := c.closeWrite()
	return err
}

func (c *pooledConn) closeWrite() (bool, error) {
	c.closeWriteOnce.Do(func() {
		if c.reusableState.Swap(poolConnClosed) != poolConnReusable {
			// relay still copies server→client; do not Close the live tunnel.
			return
		}
		c.closeWriteReusable = true
		c.closeWriteErr = c.Conn.HalfClose()
	})
	return c.closeWriteReusable, c.closeWriteErr
}

func (c *pooledConn) Close() error {
	c.once.Do(func() {
		reusable, err := c.closeWrite()
		if err != nil {
			c.closeErr = err
			_ = c.Conn.Close()
			return
		}
		if !reusable {
			c.closeErr = c.Conn.Close()
			return
		}
		if !c.Conn.PeerClosed() {
			_ = c.Conn.Close()
			return
		}
		_ = c.Conn.SetReadDeadline(time.Time{})
		c.Conn.ResetReply()
		if !c.pool.put(c.Conn) {
			c.closeErr = c.Conn.Close()
		}
	})
	return c.closeErr
}

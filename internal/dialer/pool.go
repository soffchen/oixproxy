package dialer

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/soffchen/oixproxy/internal/snell"
)

const (
	poolMaxIdle     = 10
	poolIdleAge     = 15 * time.Second
	poolMaxUses     = 2
	poolWarmTimeout = 10 * time.Second
)

var errPoolClosed = errors.New("snell 连接池已关闭")

type idleConn struct {
	c    *snell.Conn
	used time.Time
	uses int
}

// Pool 保存已完成 ECH-TLS 和 Snell PING 校验的空闲传输。
type Pool struct {
	node    Node
	factory func(context.Context) (*snell.Conn, error)

	mu     sync.Mutex
	idle   []idleConn
	closed bool
}

func NewPool(n Node) *Pool {
	p := &Pool{node: n}
	p.factory = func(ctx context.Context) (*snell.Conn, error) {
		raw, exporter, err := dialTransport(ctx, n)
		if err != nil {
			return nil, err
		}
		c := snell.NewConnIdentity(raw, []byte(n.PSK), exporter, n.identityVersion())
		if n.Reuse {
			if err := c.Warmup(ctx); err != nil {
				_ = c.Close()
				return nil, err
			}
		}
		return c, nil
	}
	return p
}

// Warm 在后台串行建立预连接；前台请求不会等待预连接完成。
func (p *Pool) Warm(n int) {
	if n <= 0 {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), poolWarmTimeout)
		defer cancel()
		for range n {
			c, err := p.factory(ctx)
			if err != nil {
				log.Printf("preconnect %s: %v", p.node.Name, err)
				return
			}
			if !p.put(c, 0) {
				_ = c.Close()
				return
			}
		}
	}()
}

func (p *Pool) Dial(ctx context.Context, n Node, network, host string, port uint16) (net.Conn, error) {
	switch network {
	case "udp", "udp4", "udp6":
		return Dial(ctx, n, network, host, port)
	}
	var last error
	for range 3 {
		sc, uses, err := p.take(ctx)
		if err != nil {
			return nil, err
		}
		deadline := time.Now().Add(20 * time.Second)
		if dl, ok := ctx.Deadline(); ok {
			deadline = dl
		}
		if err := sc.SetDeadline(deadline); err != nil {
			_ = sc.Close()
			last = err
			continue
		}
		if err := sc.WriteConnect(host, port, n.Reuse); err != nil {
			_ = sc.Close()
			last = err
			continue
		}
		if err := sc.SetDeadline(time.Time{}); err != nil {
			_ = sc.Close()
			last = err
			continue
		}
		pc := &pooledConn{Conn: sc, pool: p, uses: uses}
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
	p.mu.Unlock()
	for _, item := range idle {
		_ = item.c.Close()
	}
}

func (p *Pool) take(ctx context.Context) (*snell.Conn, int, error) {
	if c, uses, ok := p.pop(); ok {
		return c, uses + 1, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	if p.isClosed() {
		return nil, 0, errPoolClosed
	}
	c, err := p.factory(ctx)
	if err != nil {
		return nil, 0, err
	}
	if p.isClosed() {
		_ = c.Close()
		return nil, 0, errPoolClosed
	}
	return c, 1, nil
}

func (p *Pool) isClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

func (p *Pool) pop() (*snell.Conn, int, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for len(p.idle) > 0 {
		first := p.idle[0]
		p.idle[0] = idleConn{}
		p.idle = p.idle[1:]
		if now.Sub(first.used) > poolIdleAge {
			_ = first.c.Close()
			continue
		}
		return first.c, first.uses, true
	}
	return nil, 0, false
}

func (p *Pool) put(c *snell.Conn, uses int) bool {
	if uses >= poolMaxUses {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || len(p.idle) >= poolMaxIdle {
		return false
	}
	p.idle = append(p.idle, idleConn{c: c, used: time.Now(), uses: uses})
	return true
}

func (p *Pool) idleCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.idle)
}

const (
	poolConnNew int32 = iota
	poolConnReusable
	poolConnClosed
)

type pooledConn struct {
	*snell.Conn
	pool               *Pool
	uses               int
	closeWriteOnce     sync.Once
	closeWriteReusable bool
	closeWriteErr      error
	closeOnce          sync.Once
	closeErr           error
	reusableState      atomic.Int32
}

// MarkReusable 表示 CONNECT-V2 请求头已经完整发出，关闭时可以尝试回池。
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
			c.closeWriteErr = c.Conn.Close()
			return
		}
		c.closeWriteReusable = true
		c.closeWriteErr = c.Conn.HalfClose()
	})
	return c.closeWriteReusable, c.closeWriteErr
}

func (c *pooledConn) Close() error {
	c.closeOnce.Do(func() {
		reusable, err := c.closeWrite()
		if err != nil {
			c.closeErr = err
			_ = c.Conn.Close()
			return
		}
		if !reusable {
			return
		}
		if !c.Conn.PeerClosed() {
			c.closeErr = c.Conn.Close()
			return
		}
		if err := c.Conn.SetReadDeadline(time.Time{}); err != nil {
			c.closeErr = err
			_ = c.Conn.Close()
			return
		}
		c.Conn.ResetReply()
		if !c.pool.put(c.Conn, c.uses) {
			c.closeErr = c.Conn.Close()
		}
	})
	return c.closeErr
}

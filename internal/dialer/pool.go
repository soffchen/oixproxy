package dialer

import (
	"context"
	"log"
	"net"
	"sync"
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
		return snell.NewConnIdentity(raw, []byte(n.PSK), exporter, n.identityVersion()), nil
	}
	return p
}

func (p *Pool) Warm(n int) {
	if n <= 0 {
		return
	}
	for i := 0; i < n; i++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			c, err := p.factory(ctx)
			if err != nil {
				log.Printf("preconnect %s: %v", p.node.Name, err)
				return
			}
			if !p.put(c) {
				_ = c.Close()
			}
		}()
	}
}

func (p *Pool) Dial(ctx context.Context, n Node, network, host string, port uint16) (net.Conn, error) {
	switch network {
	case "udp", "udp4", "udp6":
		return Dial(ctx, n, network, host, port)
	}
	sc, err := p.take(ctx)
	if err != nil {
		return nil, err
	}
	if err := sc.WriteConnect(host, port, n.Reuse); err != nil {
		_ = sc.Close()
		return nil, err
	}
	return &pooledConn{Conn: sc, pool: p, reuse: n.Reuse}, nil
}

func (p *Pool) Close() {
	p.mu.Lock()
	p.closed = true
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()
	for _, it := range idle {
		_ = it.c.Close()
	}
}

func (p *Pool) take(ctx context.Context) (*snell.Conn, error) {
	if c := p.pop(); c != nil {
		return c, nil
	}
	return p.factory(ctx)
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
	return true
}

func (p *Pool) idleCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.idle)
}

type pooledConn struct {
	*snell.Conn
	pool     *Pool
	reuse    bool
	hcOnce   sync.Once
	hcErr    error
	once     sync.Once
	closeErr error
}

func (c *pooledConn) CloseWrite() error {
	if !c.reuse {
		return nil
	}
	return c.halfClose()
}

func (c *pooledConn) halfClose() error {
	c.hcOnce.Do(func() {
		c.hcErr = c.Conn.HalfClose()
	})
	return c.hcErr
}

func (c *pooledConn) Close() error {
	c.once.Do(func() {
		if !c.reuse {
			c.closeErr = c.Conn.Close()
			return
		}
		if err := c.halfClose(); err != nil {
			c.closeErr = err
			_ = c.Conn.Close()
			return
		}
		if !c.Conn.PeerClosed() {
			c.closeErr = c.Conn.Close()
			return
		}
		c.Conn.ResetReply()
		if !c.pool.put(c.Conn) {
			c.closeErr = c.Conn.Close()
		}
	})
	return c.closeErr
}

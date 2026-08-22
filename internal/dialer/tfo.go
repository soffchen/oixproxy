package dialer

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	tfo "github.com/metacubex/tfo-go"
)

// tfoConn delays TCP until the first Write so TLS ClientHello can ride TFO.
type tfoConn struct {
	once      sync.Once
	conn      net.Conn
	err       error
	ctx       context.Context
	cancel    context.CancelFunc
	dialFn    func(ctx context.Context, early []byte) (net.Conn, error)
	mu        sync.Mutex
	closed    bool
	rdeadline time.Time
	wdeadline time.Time
}

func newTFOConn(parent context.Context, dests []string, base net.Dialer) net.Conn {
	ctx, cancel := context.WithCancel(parent)
	return &tfoConn{
		ctx:    ctx,
		cancel: cancel,
		dialFn: func(ctx context.Context, early []byte) (net.Conn, error) {
			td := tfo.Dialer{Dialer: base, DisableTFO: false}
			var last error
			for _, dest := range dests {
				c, err := td.DialContext(ctx, "tcp", dest, early)
				if err == nil {
					return c, nil
				}
				last = err
			}
			if last == nil {
				last = io.ErrUnexpectedEOF
			}
			return nil, last
		},
	}
}

func (c *tfoConn) publish(conn net.Conn, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		if conn != nil {
			_ = conn.Close()
		}
		if c.err == nil {
			c.err = io.ErrClosedPipe
		}
		return
	}
	if conn != nil && err == nil {
		if e := conn.SetReadDeadline(c.rdeadline); e != nil {
			_ = conn.Close()
			c.err = e
			return
		}
		if e := conn.SetWriteDeadline(c.wdeadline); e != nil {
			_ = conn.Close()
			c.err = e
			return
		}
	}
	c.conn, c.err = conn, err
}

func (c *tfoConn) ensure(early []byte) error {
	c.once.Do(func() {
		c.publish(c.dialFn(c.ctx, early))
	})
	return c.err
}

func (c *tfoConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	c.mu.Unlock()
	first := false
	c.once.Do(func() {
		first = true
		c.publish(c.dialFn(c.ctx, b))
	})
	if c.err != nil {
		return 0, c.err
	}
	if first {
		return len(b), nil
	}
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return 0, io.ErrClosedPipe
	}
	return conn.Write(b)
}

func (c *tfoConn) Read(b []byte) (int, error) {
	if err := c.ensure(nil); err != nil {
		return 0, err
	}
	c.mu.Lock()
	conn, closed := c.conn, c.closed
	c.mu.Unlock()
	if closed || conn == nil {
		return 0, io.ErrClosedPipe
	}
	return conn.Read(b)
}

func (c *tfoConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.cancel()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *tfoConn) LocalAddr() net.Addr {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		return conn.LocalAddr()
	}
	return &net.TCPAddr{}
}

func (c *tfoConn) RemoteAddr() net.Addr {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		return conn.RemoteAddr()
	}
	return &net.TCPAddr{}
}

func (c *tfoConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rdeadline = t
	c.wdeadline = t
	if c.conn == nil {
		return nil
	}
	if err := c.conn.SetReadDeadline(t); err != nil {
		return err
	}
	return c.conn.SetWriteDeadline(t)
}

func (c *tfoConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rdeadline = t
	if c.conn == nil {
		return nil
	}
	return c.conn.SetReadDeadline(t)
}

func (c *tfoConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wdeadline = t
	if c.conn == nil {
		return nil
	}
	return c.conn.SetWriteDeadline(t)
}

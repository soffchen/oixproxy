package dialer

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestTFOConnFirstWriteIsEarlyData(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var got []byte
	c := &tfoConn{
		ctx:    ctx,
		cancel: cancel,
		dialFn: func(ctx context.Context, early []byte) (net.Conn, error) {
			got = append([]byte(nil), early...)
			a, b := net.Pipe()
			go func() {
				_, _ = io.Copy(io.Discard, b)
				_ = b.Close()
			}()
			return a, nil
		},
	}
	n, err := c.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Fatalf("write %d %v", n, err)
	}
	if string(got) != "hello" {
		t.Fatalf("early %q", got)
	}
	if _, err := c.Write([]byte("more")); err != nil {
		t.Fatal(err)
	}
}

func TestTFOConnCloseBeforeDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := &tfoConn{ctx: ctx, cancel: cancel, dialFn: func(context.Context, []byte) (net.Conn, error) {
		t.Fatal("should not dial")
		return nil, nil
	}}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("x")); err != io.ErrClosedPipe {
		t.Fatalf("write after close %v", err)
	}
}

func TestTFOConnCloseDuringDialClosesLeftover(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	closed := make(chan struct{})
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	go func() {
		_, _ = io.Copy(io.Discard, b)
		_ = b.Close()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	c := &tfoConn{
		ctx:    ctx,
		cancel: cancel,
		dialFn: func(ctx context.Context, early []byte) (net.Conn, error) {
			close(started)
			<-release
			return &closeNotify{Conn: a, ch: closed}, nil
		},
	}
	errCh := make(chan error, 1)
	go func() {
		_, err := c.Write([]byte("hello"))
		errCh <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("dial did not start")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("leftover conn not closed")
	}
	select {
	case err := <-errCh:
		if err != io.ErrClosedPipe {
			t.Fatalf("write %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write hung")
	}
}

func TestTFOConnAppliesDeadlineAfterDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dc := &deadlineConn{}
	c := &tfoConn{
		ctx:    ctx,
		cancel: cancel,
		dialFn: func(ctx context.Context, early []byte) (net.Conn, error) {
			a, b := net.Pipe()
			go func() {
				_, _ = io.Copy(io.Discard, b)
				_ = b.Close()
			}()
			dc.Conn = a
			return dc, nil
		},
	}
	want := time.Now().Add(time.Hour).Round(time.Second)
	if err := c.SetDeadline(want); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if !dc.read.Equal(want) || !dc.write.Equal(want) {
		t.Fatalf("deadlines r=%v w=%v want %v", dc.read, dc.write, want)
	}
	_ = c.LocalAddr()
	_ = c.RemoteAddr()
}

type deadlineConn struct {
	net.Conn
	read, write time.Time
}

func (c *deadlineConn) SetReadDeadline(t time.Time) error {
	c.read = t
	if c.Conn != nil {
		return c.Conn.SetReadDeadline(t)
	}
	return nil
}

func (c *deadlineConn) SetWriteDeadline(t time.Time) error {
	c.write = t
	if c.Conn != nil {
		return c.Conn.SetWriteDeadline(t)
	}
	return nil
}

type closeNotify struct {
	net.Conn
	once sync.Once
	ch   chan struct{}
}

func (c *closeNotify) Close() error {
	c.once.Do(func() { close(c.ch) })
	return c.Conn.Close()
}

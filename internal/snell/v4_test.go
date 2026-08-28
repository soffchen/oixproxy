package snell

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
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

func TestReadReplyRejectsLeftoverZeroChunk(t *testing.T) {
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
	err = client.ReadReply()
	if !errors.Is(err, ErrZeroChunk) {
		t.Fatalf("遗留零块错误为 %v", err)
	}
}

func TestReadReplyPrematureEOFIsProtocolError(t *testing.T) {
	a, b := net.Pipe()
	client := NewConnIdentity(a, []byte("test-psk"), nil, 2)
	_ = b.Close()
	t.Cleanup(func() { _ = a.Close() })

	err := client.ReadReply()
	if err == io.EOF {
		t.Fatal("提前关闭不能作为正常 EOF 返回")
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("错误为 %v，期望包含 EOF", err)
	}
}

func readWarmupPing(peer *Conn) error {
	if peer.r == nil {
		if err := peer.initReader(); err != nil {
			return err
		}
	}
	p, err := peer.r.readFrame()
	if err != nil {
		return err
	}
	want := []byte{headerVersion, cmdPing, 0}
	if !bytes.Equal(p, want) {
		return fmt.Errorf("PING 为 %v，期望 %v", p, want)
	}
	return nil
}

func TestWarmupPongKeepsConnectionForConnect(t *testing.T) {
	client, peer := pipeConns(t)
	errc := make(chan error, 1)
	host := "example.com"
	go func() {
		if err := readWarmupPing(peer); err != nil {
			errc <- err
			return
		}
		if _, err := peer.Write([]byte{cmdPong}); err != nil {
			errc <- err
			return
		}
		req, err := peer.r.readFrame()
		if err != nil {
			errc <- err
			return
		}
		want := []byte{headerVersion, cmdConnectV2, 0, byte(len(host))}
		want = append(want, host...)
		want = append(want, 0x01, 0xbb)
		if !bytes.Equal(req, want) {
			errc <- fmt.Errorf("预热后的请求头为 %v", req)
			return
		}
		if _, err := peer.Write([]byte{cmdTunnel}); err != nil {
			errc <- err
			return
		}
		if _, err := peer.Write([]byte("ok")); err != nil {
			errc <- err
			return
		}
		errc <- peer.HalfClose()
	}()
	if err := client.Warmup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := client.WriteConnect(host, 443, true); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	n, err := client.Read(buf)
	if err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("同一传输读取 %q：%v", buf[:n], err)
	}
	if _, err := client.Read(buf); err != io.EOF {
		t.Fatalf("同一传输结束错误为 %v", err)
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

func TestWarmupRejectsUnexpectedReply(t *testing.T) {
	client, peer := pipeConns(t)
	errc := make(chan error, 1)
	go func() {
		if err := readWarmupPing(peer); err != nil {
			errc <- err
			return
		}
		if _, err := peer.Write([]byte{cmdTunnel}); err != nil {
			errc <- err
			return
		}
		errc <- nil
	}()
	err := client.Warmup(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unexpected Snell warmup reply") {
		t.Fatalf("意外回复错误为 %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestWarmupHonorsContextDeadline(t *testing.T) {
	client, peer := pipeConns(t)
	pingRead := make(chan error, 1)
	go func() {
		pingRead <- readWarmupPing(peer)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := client.Warmup(ctx)
	if err == nil {
		t.Fatal("预热等待 PONG 应超时")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("预热超时耗时过长：%s", time.Since(start))
	}
	if err := <-pingRead; err != nil {
		t.Fatal(err)
	}
}

type shortWriter struct {
	bytes.Buffer
	max int
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > w.max {
		p = p[:w.max]
	}
	return w.Buffer.Write(p)
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

func TestWriteFullHandlesShortWrites(t *testing.T) {
	w := &shortWriter{max: 3}
	want := []byte("0123456789")
	if err := writeFull(w, want); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(w.Bytes(), want) {
		t.Fatalf("写入结果为 %q", w.Bytes())
	}
	if err := writeFull(zeroWriter{}, want); err != io.ErrShortWrite {
		t.Fatalf("零字节短写错误为 %v", err)
	}
}

func TestV4WriterCompletesShortUnderlyingWrites(t *testing.T) {
	const psk = "test-psk"
	raw := &shortWriter{max: 3}
	w, err := newWriter(raw, []byte(psk), nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("payload")
	if _, err := w.Write(want); err != nil {
		t.Fatal(err)
	}
	data := raw.Bytes()
	if len(data) <= saltSize {
		t.Fatalf("底层只写入了 %d 字节", len(data))
	}
	aead, err := newAESGCM(kdf([]byte(psk), data[:saltSize]))
	if err != nil {
		t.Fatal(err)
	}
	r := &v4Reader{r: bytes.NewReader(data[saltSize:]), aead: aead}
	got, err := r.readFrame()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("解密载荷为 %q，期望 %q", got, want)
	}
}

func TestFirstPayloadLimitIncludesIdentityPrefix(t *testing.T) {
	const padding = 0x100
	tests := []struct {
		name            string
		identityVersion int
		exporterSize    int
		identity        int
	}{
		{name: "无身份头"},
		{name: "DLSNID01", identityVersion: 1, identity: 24},
		{name: "DLSNID02", identityVersion: 2, exporterSize: 32, identity: 40},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := v4Writer{
				initPad:         padding,
				identityVersion: tt.identityVersion,
				exporter:        make([]byte, tt.exporterSize),
			}
			want := uint16(frameSize - 55 - padding - tt.identity)
			if got := w.nextPayloadLimit(); got != want {
				t.Fatalf("首帧载荷上限为 %d，期望 %d", got, want)
			}
		})
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

func BenchmarkV4WriterWrite32K(b *testing.B) {
	w, err := newWriter(io.Discard, []byte("benchmark-psk"), nil, 1)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := w.Write([]byte("warmup")); err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 32*1024)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := w.Write(payload); err != nil {
			b.Fatal(err)
		}
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

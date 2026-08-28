package snell

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestUDPRequestIPv4RoundTripShape(t *testing.T) {
	pkt, err := encodeUDPRequest("1.2.3.4", 53, []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{cmdUDPForward, 0x00, 0x04, 1, 2, 3, 4, 0, 53, 'a', 'b', 'c'}
	if !bytes.Equal(pkt, want) {
		t.Fatalf("%x", pkt)
	}
}

func TestUDPRequestDomain(t *testing.T) {
	pkt, err := encodeUDPRequest("dns.google", 53, []byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if pkt[0] != cmdUDPForward || pkt[1] != byte(len("dns.google")) {
		t.Fatalf("%x", pkt)
	}
	if string(pkt[2:2+len("dns.google")]) != "dns.google" {
		t.Fatal(string(pkt))
	}
}

func TestUDPResponseParse(t *testing.T) {
	raw := []byte{0x04, 8, 8, 8, 8, 0, 53, 9, 9}
	addr, payload, err := parseUDPResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	ua := addr.(*net.UDPAddr)
	if !ua.IP.Equal(net.IPv4(8, 8, 8, 8)) || ua.Port != 53 {
		t.Fatalf("%v", ua)
	}
	if !bytes.Equal(payload, []byte{9, 9}) {
		t.Fatalf("%x", payload)
	}
}

func TestPacketConnRoundTrip(t *testing.T) {
	client, peer := pipeConns(t)
	errCh := make(chan error, 1)
	go func() {
		if err := peer.initReader(); err != nil {
			errCh <- err
			return
		}
		header, err := peer.r.readFrame()
		if err != nil {
			errCh <- err
			return
		}
		if len(header) != 3 || header[0] != headerVersion || header[1] != cmdUDP {
			errCh <- io.ErrUnexpectedEOF
			return
		}
		replyDone := make(chan error, 1)
		go func() {
			_, err := peer.Write([]byte{cmdTunnel})
			replyDone <- err
		}()
		request, err := peer.r.readFrame()
		if err != nil || len(request) == 0 || request[0] != cmdUDPForward {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			errCh <- err
			return
		}
		if err := <-replyDone; err != nil {
			errCh <- err
			return
		}
		response := []byte{0x04, 1, 1, 1, 1, 0, 53, 'o', 'k'}
		_, err = peer.WritePacket(response)
		errCh <- err
	}()
	if err := client.WriteUDP(); err != nil {
		t.Fatal(err)
	}
	pc := NewPacketConn(client)
	if _, err := pc.WriteTo([]byte("query"), &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "ok" || addr.String() != "1.1.1.1:53" {
		t.Fatalf("reply %q from %v", buf[:n], addr)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("peer 未完成 UDP round trip")
	}
}

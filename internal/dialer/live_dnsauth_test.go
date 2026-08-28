package dialer

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLive1053DNSAuthReturnsWorkingIP(t *testing.T) {
	if os.Getenv("OIX_LIVE_SOCKS") != "1" {
		t.Skip("OIX_LIVE_SOCKS=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	host := os.Getenv("OIX_LIVE_HOST")
	if host == "" {
		t.Skip("OIX_LIVE_HOST")
	}
	ns := []DNSServer{{Network: "udp", Addr: CloudNodesDNS}}
	ips, err := LookupServers(ctx, host, ns)
	if err != nil {
		t.Fatal("live DNS-Auth lookup failed")
	}
	if len(ips) == 0 {
		t.Fatal("live DNS-Auth returned no addresses")
	}
	got := ips[0].To4()
	if got == nil {
		t.Fatal("live DNS-Auth returned a non-IPv4 address")
	}
	if got.String() == "119.40.182.189" {
		t.Fatal("live DNS-Auth returned decoy A from unsigned QNAME")
	}
}

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
	ns := []DNSServer{{Network: "udp", Addr: CloudNodesDNS}}
	for _, host := range []string{"fusion_hk_1.cloud-nodes.com", "fusion_hk_13.cloud-nodes.com", "fusion_jp_12.cloud-nodes.com"} {
		ips, err := LookupServers(ctx, host, ns)
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if len(ips) == 0 {
			t.Fatalf("%s empty", host)
		}
		got := ips[0].To4()
		if got == nil {
			t.Fatalf("%s not v4", host)
		}
		if got.String() == "119.40.182.189" {
			t.Fatalf("%s decoy A from unsigned QNAME", host)
		}
		t.Logf("%s resolved to a non-decoy IPv4", host)
	}
}

package run

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthcheckAddressesIncludeBothLoopbackFamilies(t *testing.T) {
	addrs, err := healthcheckAddrs("6172")
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 2 || addrs[0] != "127.0.0.1:6172" || addrs[1] != "[::1]:6172" {
		t.Fatalf("addrs=%v", addrs)
	}
	colonAddrs, err := healthcheckAddrs(":6172")
	if err != nil || strings.Join(colonAddrs, ",") != strings.Join(addrs, ",") {
		t.Fatalf("colon addrs=%v err=%v", colonAddrs, err)
	}
	explicit, err := healthcheckAddrs("[::1]:6172")
	if err != nil || len(explicit) != 1 || explicit[0] != "[::1]:6172" {
		t.Fatalf("explicit=%v err=%v", explicit, err)
	}
	if _, err := healthcheckAddrs("not-an-address"); err == nil {
		t.Fatal("无效地址应失败")
	}
}

func TestHealthcheckRequiresExactHealthyBody(t *testing.T) {
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	}))
	defer healthy.Close()
	if err := Healthcheck(strings.TrimPrefix(healthy.URL, "http://")); err != nil {
		t.Fatal(err)
	}
	unhealthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("starting\n"))
	}))
	defer unhealthy.Close()
	if err := Healthcheck(strings.TrimPrefix(unhealthy.URL, "http://")); err == nil {
		t.Fatal("非 ok 响应不应通过健康检查")
	}
	oversized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok" + strings.Repeat(" ", 62) + "x"))
	}))
	defer oversized.Close()
	if err := Healthcheck(strings.TrimPrefix(oversized.URL, "http://")); err == nil {
		t.Fatal("超过上限的响应不应被截断为 ok")
	}
}

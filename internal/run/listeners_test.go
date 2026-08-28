package run

import (
	"strings"
	"testing"

	"github.com/soffchen/oixproxy/internal/config"
	"github.com/soffchen/oixproxy/internal/dialer"
)

func listenerNodes() []dialer.Node {
	return []dialer.Node{
		{Name: "香港 01", Server: "hk.example", Port: 443},
		{Name: "日本 01", Server: "jp.example", Port: 443},
	}
}

func TestExtraListenersUseConfiguredUniqueNames(t *testing.T) {
	cfg := config.Defaults()
	cfg.Listeners = []config.Listener{
		{Name: "固定香港", Port: 7801, Node: "香港 01"},
		{Name: "固定日本", Port: 7802, Node: "日本 01", Listen: "[::1]"},
	}
	extras, err := extraListeners(cfg, listenerNodes(), listenerNodes(), nil, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(extras) != 2 {
		t.Fatalf("extras=%d", len(extras))
	}
	if extras[0].Name != "固定香港" || extras[0].Node.Name != "香港 01" || extras[0].Addr != "127.0.0.1:7801" {
		t.Fatalf("香港 listener: %+v", extras[0])
	}
	if extras[1].Name != "固定日本" || extras[1].Node.Name != "日本 01" || extras[1].Addr != "[::1]:7802" {
		t.Fatalf("日本 listener: %+v", extras[1])
	}
}

func TestExtraListenersRejectInvalidConfig(t *testing.T) {
	tests := []struct {
		name     string
		listener config.Listener
		want     string
	}{
		{name: "缺少名称", listener: config.Listener{Port: 7801, Node: "香港 01"}, want: "name"},
		{name: "名称与基础节点重复", listener: config.Listener{Name: "香港 01", Port: 7801, Node: "香港 01"}, want: "duplicate"},
		{name: "节点不存在", listener: config.Listener{Name: "固定香港", Port: 7801, Node: "不存在"}, want: "not found"},
		{name: "端口为零", listener: config.Listener{Name: "固定香港", Port: 0, Node: "香港 01"}, want: "port"},
		{name: "端口溢出", listener: config.Listener{Name: "固定香港", Port: 65536, Node: "香港 01"}, want: "port"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Listeners = []config.Listener{tt.listener}
			if _, err := extraListeners(cfg, listenerNodes(), listenerNodes(), nil, "127.0.0.1"); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err=%v want %q", err, tt.want)
			}
		})
	}
}

func TestExtraListenersRejectDuplicateAliases(t *testing.T) {
	cfg := config.Defaults()
	cfg.Listeners = []config.Listener{
		{Name: "固定节点", Port: 7801, Node: "香港 01"},
		{Name: "固定节点", Port: 7802, Node: "日本 01"},
	}
	if _, err := extraListeners(cfg, listenerNodes(), listenerNodes(), nil, "127.0.0.1"); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("err=%v", err)
	}
}

func TestExtraListenersSkipInactiveNodes(t *testing.T) {
	all := listenerNodes()
	active := all[:1]
	cfg := config.Defaults()
	cfg.Listeners = []config.Listener{
		{Name: "固定香港", Port: 7801, Node: "香港 01"},
		{Name: "固定日本", Port: 7802, Node: "日本 01"},
	}
	extras, err := extraListeners(cfg, active, all, nil, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(extras) != 1 || extras[0].Name != "固定香港" {
		t.Fatalf("extras=%+v", extras)
	}
}

func TestExtraListenersIgnoreMapConfigInSingleMode(t *testing.T) {
	cfg := config.Defaults()
	cfg.ProxyMode = "single"
	cfg.Listeners = []config.Listener{{Name: "", Port: 0, Node: "不存在"}}
	extras, err := extraListeners(cfg, listenerNodes()[:1], listenerNodes(), nil, "127.0.0.1")
	if err != nil || len(extras) != 0 {
		t.Fatalf("extras=%v err=%v", extras, err)
	}
}

func TestExtraListenersStillRejectUnknownNodeWhenFiltered(t *testing.T) {
	all := listenerNodes()
	cfg := config.Defaults()
	cfg.Listeners = []config.Listener{{Name: "固定未知", Port: 7801, Node: "不存在"}}
	if _, err := extraListeners(cfg, all[:1], all, nil, "127.0.0.1"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err=%v", err)
	}
}

func TestExtraListenersRejectUnsafeAliases(t *testing.T) {
	unsafe := []string{
		"换行\n节点",
		"逗号,节点",
		"等号=节点",
		"双引号\"节点",
		`尾随\`,
		"#注释",
		";注释",
		"Direct",
		"block",
		"Proxy",
		"Auto - UrlTest",
		"Auto - Smart",
		"oixCloud",
	}
	for _, name := range unsafe {
		t.Run(name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Listeners = []config.Listener{{Name: name, Port: 7801, Node: "香港 01"}}
			if _, err := extraListeners(cfg, listenerNodes(), listenerNodes(), nil, "127.0.0.1"); err == nil {
				t.Fatalf("名称 %q 应被拒绝", name)
			}
		})
	}
	if err := validateListenerName("🇭🇰 固定香港 Premium"); err != nil {
		t.Fatalf("正常名称被拒绝: %v", err)
	}
}

func TestExtraListenersRejectTemplateGroupNames(t *testing.T) {
	template := []byte(`[Proxy Group]
Domestic = select, Direct
AdBlock = select, Block, Direct
`)
	for _, name := range []string{"Domestic", "domestic", "AdBlock"} {
		t.Run(name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Listeners = []config.Listener{{Name: name, Port: 7801, Node: "香港 01"}}
			if _, err := extraListeners(cfg, listenerNodes(), listenerNodes(), template, "127.0.0.1"); err == nil || !strings.Contains(err.Error(), "duplicate") {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

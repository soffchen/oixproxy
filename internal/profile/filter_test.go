package profile

import (
	"strings"
	"testing"

	"github.com/soffchen/oixproxy/internal/dialer"
)

func sampleNodes() []dialer.Node {
	names := []string{
		"🇭🇰 香港 Fusion 01",
		"🇭🇰 香港 Fusion 13 [Premium]",
		"🇯🇵 日本 Fusion 01",
		"🇯🇵 日本 Fusion 09 [Advanced]",
		"🇺🇸 美国 Fusion 01",
		"🇭🇰 香港 Fusion 14 [Premium]",
	}
	out := make([]dialer.Node, len(names))
	for i, n := range names {
		out[i] = dialer.Node{Name: n}
	}
	return out
}

func namesOf(nodes []dialer.Node) []string {
	s := make([]string, len(nodes))
	for i, n := range nodes {
		s[i] = n.Name
	}
	return s
}

func TestFilterEmptyKeepsAll(t *testing.T) {
	in := sampleNodes()
	got, err := Filter(in, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(in) {
		t.Fatalf("len %d", len(got))
	}
}

func TestFilterBacktickOROrder(t *testing.T) {
	got, err := Filter(sampleNodes(), "香港.*Premium`日本")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"🇭🇰 香港 Fusion 13 [Premium]",
		"🇭🇰 香港 Fusion 14 [Premium]",
		"🇯🇵 日本 Fusion 01",
		"🇯🇵 日本 Fusion 09 [Advanced]",
	}
	if strings.Join(namesOf(got), "\n") != strings.Join(want, "\n") {
		t.Fatalf("got %v", namesOf(got))
	}
}

func TestFilterKeyword(t *testing.T) {
	got, err := Filter(sampleNodes(), "日本")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !strings.Contains(got[0].Name, "日本") {
		t.Fatalf("%v", namesOf(got))
	}
}

func TestFilterNoMatch(t *testing.T) {
	got, err := Filter(sampleNodes(), "不存在的区域")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("%v", namesOf(got))
	}
}

func TestFilterBadRegexp(t *testing.T) {
	_, err := Filter(sampleNodes(), "[invalid")
	if err == nil {
		t.Fatal("expected error")
	}
}

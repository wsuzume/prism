package domain

import (
	"testing"
)

func TestIsIPv4(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		// 正常な IPv4
		{"192.168.1.1", true},
		{"0.0.0.0", true},
		{"255.255.255.255", true},
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		// IPv6 は false
		{"::1", false},
		{"2001:db8::1", false},
		{"::ffff:192.0.2.1", true}, // IPv4-mapped IPv6: Go の net パッケージは IPv4 として扱う
		// ホスト名は false
		{"example.com", false},
		{"localhost", false},
		// 空・不正
		{"", false},
		{"999.999.999.999", false},
		{"192.168.1", false},
		{"192.168.1.1.1", false},
		// ブラケット付きは false（IPv4 に括弧は不要）
		{"[192.168.1.1]", false},
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			got := IsIPv4(c.input)
			if got != c.want {
				t.Errorf("IsIPv4(%q) = %v, want %v", c.input, got, c.want)
			}
		})
	}
}

func TestIsIPv6(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		// 正常な IPv6
		{"::1", true},
		{"2001:db8::1", true},
		{"fe80::1", true},
		{"::ffff:192.0.2.1", false}, // IPv4-mapped IPv6: Go の net パッケージは To4() が非 nil のため IPv4 扱い
		// ブラケット付き
		{"[::1]", true},
		{"[2001:db8::1]", true},
		// IPv4 は false
		{"192.168.1.1", false},
		{"127.0.0.1", false},
		// ホスト名は false
		{"example.com", false},
		{"localhost", false},
		// 空・不正
		{"", false},
		{"not-an-ip", false},
		// ポート付きは false（SplitPort を通さずに渡した場合）
		{"[::1]:8080", false},
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			got := IsIPv6(c.input)
			if got != c.want {
				t.Errorf("IsIPv6(%q) = %v, want %v", c.input, got, c.want)
			}
		})
	}
}

func TestSplitPort(t *testing.T) {
	cases := []struct {
		input    string
		wantHost string
		wantPort string
	}{
		// host:port
		{"example.com:8080", "example.com", "8080"},
		{"example.com:80", "example.com", "80"},
		{"localhost:3000", "localhost", "3000"},
		// ポートなし
		{"example.com", "example.com", ""},
		{"localhost", "localhost", ""},
		{"192.168.1.1", "192.168.1.1", ""},
		// IPv6 with port
		{"[::1]:8080", "::1", "8080"},
		{"[2001:db8::1]:443", "2001:db8::1", "443"},
		// IPv6 without port (ブラケットなし)
		{"::1", "::1", ""},
		// IPv6 ブラケット付きポートなし — net.SplitHostPort は失敗するので入力をそのまま返す
		{"[::1]", "[::1]", ""},
		// 空文字
		{"", "", ""},
		// 前後スペース
		{"  example.com:8080  ", "example.com", "8080"},
		{"  example.com  ", "example.com", ""},
		// ポート番号 0
		{"example.com:0", "example.com", "0"},
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			gotHost, gotPort := SplitPort(c.input)
			if gotHost != c.wantHost || gotPort != c.wantPort {
				t.Errorf("SplitPort(%q) = (%q, %q), want (%q, %q)",
					c.input, gotHost, gotPort, c.wantHost, c.wantPort)
			}
		})
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		// 通常のホスト名
		{"example.com", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"Api.Example.Com", "api.example.com"},
		// サブドメイン
		{"sub.example.com", "sub.example.com"},
		// IP
		{"192.168.1.1", "192.168.1.1"},
		{"::1", "::1"},
		// 前後スペース
		{"  example.com  ", "example.com"},
		// 空文字
		{"", ""},
		// localhost
		{"Localhost", "localhost"},
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			got := NormalizeHost(c.input)
			if got != c.want {
				t.Errorf("NormalizeHost(%q) = %q, want %q", c.input, got, c.want)
			}
		})
	}
}

func TestExtractSubdomain(t *testing.T) {
	cases := []struct {
		host       string
		baseDomain string
		want       string
	}{
		// 通常のサブドメイン
		{"api.example.com", "example.com", "api"},
		{"v2.api.example.com", "example.com", "v2.api"},
		// ルートドメイン
		{"example.com", "example.com", ""},
		// 大文字混在
		{"API.Example.Com", "example.com", "api"},
		{"api.example.com", "Example.Com", "api"},
		// 関係ないドメイン
		{"other.com", "example.com", ""},
		{"evil-example.com", "example.com", ""},
		{"notexample.com", "example.com", ""},
		// 空
		{"", "example.com", ""},
		{"api.example.com", "", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		name := c.host + "|" + c.baseDomain
		t.Run(name, func(t *testing.T) {
			got := ExtractSubdomain(c.host, c.baseDomain)
			if got != c.want {
				t.Errorf("ExtractSubdomain(%q, %q) = %q, want %q",
					c.host, c.baseDomain, got, c.want)
			}
		})
	}
}

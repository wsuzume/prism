package domain

import (
	"net"
	"strings"
)

// IsIPv4 はホスト名が IPv4 アドレスかどうかを返す。
func IsIPv4(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() != nil
}

// IsIPv6 はホスト名が IPv6 アドレスかどうかを返す。
// ブラケット付き ("[::1]") も受け付ける。
func IsIPv6(host string) bool {
	h := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(host), "]"), "[")
	ip := net.ParseIP(h)
	return ip != nil && ip.To4() == nil
}

// SplitPort はホスト名(またはホスト:ポート文字列)からホストとポートを返す。
// ポートがない場合、port は空文字列。
func SplitPort(hostport string) (host, port string) {
	h, p, err := net.SplitHostPort(strings.TrimSpace(hostport))
	if err != nil {
		return strings.TrimSpace(hostport), ""
	}
	return h, p
}

// NormalizeHost はポートなしのホスト名を小文字化して返す。
// 例: "api.example.com" -> "api.example.com"
func NormalizeHost(host string) string {
	return strings.ToLower(strings.TrimSpace(host))
}

// baseDomain を基準に subdomain を取り出す。
// 例: host="api.example.com", baseDomain="example.com" -> "api"
//
//	host="example.com", baseDomain="example.com" -> "" (ルート扱い)
func ExtractSubdomain(host, baseDomain string) string {
	host = NormalizeHost(host)
	baseDomain = strings.ToLower(strings.TrimSpace(baseDomain))

	if host == "" || baseDomain == "" {
		return ""
	}
	if host == baseDomain {
		return ""
	}
	suffix := "." + baseDomain
	if strings.HasSuffix(host, suffix) {
		left := strings.TrimSuffix(host, suffix) // "api" or "a.b"
		// 必要なら "a.b" を許す/禁止するなど方針で変えてください
		return left
	}
	return "" // 想定外ドメイン
}

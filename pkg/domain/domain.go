package domain

import (
	"net"
	"strings"
)

// Hostヘッダから "hostname" 部分を取り出して小文字化。
// 例: "api.example.com:8080" -> "api.example.com"
func NormalizeHost(hostport string) string {
	h := strings.TrimSpace(hostport)
	if h == "" {
		return ""
	}

	// IPv6対応: [::1]:8080 など
	if strings.HasPrefix(h, "[") {
		if host, _, err := net.SplitHostPort(h); err == nil {
			return strings.ToLower(host)
		}
		return strings.ToLower(strings.Trim(h, "[]"))
	}

	// 通常の host:port
	if host, _, err := net.SplitHostPort(h); err == nil {
		return strings.ToLower(host)
	}
	return strings.ToLower(h)
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

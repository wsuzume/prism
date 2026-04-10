package domain

import (
	"net"
	"strings"
)

// ドメイン関連のユーティリティ関数を提供するパッケージ。

// Prism が想定している一般的な URI のドメイン構造は以下の通り。
//
//   [hostname].[tenant].[baseDoamain]:[port]/[route]
// 
// 例:
//   example.com -> hostname="", tenant="", baseDomain=example.com, route=""
//   example.com/v1 -> hostname="", tenant="", baseDomain=example.com, route="v1"
//   api.example.com -> hostname="", tenant=api, baseDomain=example.com, route=""
//   api.example.com/v1 -> hostname="", tenant=api, baseDomain=example.com, route="v1"
//   api.tenant1.example.com -> hostname=api, tenant=tenant1, baseDomain=example.com, route=""
//   api.tenant1.example.com/v1 -> hostname=api, tenant=tenant1, baseDomain=example.com, route="v1"
//   userA.api.tenant1.example.com -> hostname=userA.api, tenant=tenant1, baseDomain=example.com, route=""
//   userA.api.tenant1.example.com/v1 -> hostname=userA.api, tenant=tenant1, baseDomain=example.com, route="v1"
// 
// その他、IPアドレスやポート番号を含む URI を受理する。
// ただしIPアドレスの場合は hostname と tenant の指定はできない。
// （そもそもブラウザがサポートしていないので到達しない）

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

type DomainParts struct {
	Hostname   string // 例: "userA.api"
	Tenant     string // 例: "tenant1"
	BaseDomain string // 例: "example.com"
	Port       string // 例: "8080"
	Route      string // 例: "v1"
}

// ParseDomain はルーティングの基準となる baseDomain を指定して、
// hostport と route から DomainParts を抽出する。
//
// hostport はポート番号を含んでもよい（例: "api.tenant1.example.com:8080"）。
// route はパス部分から呼び出し元が抽出した文字列をそのまま渡す（例: "v1"）。
//
// IP アドレスの場合、または baseDomain が空・不一致の場合は
// Hostname と Tenant は空文字列になる。
func ParseDomain(hostport, baseDomain, route string) DomainParts {
	host, port := SplitPort(hostport)
	host = NormalizeHost(host)
	baseDomain = strings.ToLower(strings.TrimSpace(baseDomain))

	result := DomainParts{
		BaseDomain: baseDomain,
		Port:       port,
		Route:      route,
	}

	if host == "" || baseDomain == "" || IsIPv4(host) || IsIPv6(host) {
		return result
	}

	if host == baseDomain {
		return result
	}

	suffix := "." + baseDomain
	if !strings.HasSuffix(host, suffix) {
		return result // 想定外ドメイン
	}

	left := strings.TrimSuffix(host, suffix) // 例: "api", "api.tenant1", "userA.api.tenant1"
	labels := strings.Split(left, ".")

	result.Tenant = labels[len(labels)-1]
	if len(labels) > 1 {
		result.Hostname = strings.Join(labels[:len(labels)-1], ".")
	}

	return result
}

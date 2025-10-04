package iprange

import (
	"bytes"
	"fmt"
	"net"
	"regexp"
	"strings"
)

//
// ──────────────────────────────────────────────────────────────────────────────
//  IP Range interface and structs
// ──────────────────────────────────────────────────────────────────────────────
//

type Family uint8

const (
	V4Family Family = iota
	V6Family
)

type Range interface {
	Family() Family
	Contains(ip net.IP) bool
}

type v4Range struct {
	start net.IP
	end   net.IP
}

func (r *v4Range) Family() Family {
	return V4Family
}

func (r *v4Range) Contains(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return bytes.Compare(v4, r.start) >= 0 && bytes.Compare(v4, r.end) <= 0
}

type v6Range struct {
	start net.IP
	end   net.IP
}

func (r *v6Range) Family() Family {
	return V6Family
}

func (r *v6Range) Contains(ip net.IP) bool {
	v6 := ip.To16()
	if v6 == nil || ip.To4() != nil { // v4は除外
		return false
	}
	return bytes.Compare(v6, r.start) >= 0 && bytes.Compare(v6, r.end) <= 0
}

type Pool []Range

func (p *Pool) Contains(ip net.IP) bool {
	if p == nil || ip == nil {
		return false
	}
	for _, r := range *p {
		if r != nil && r.Contains(ip) {
			return true
		}
	}
	return false
}

//
// ──────────────────────────────────────────────────────────────────────────────
//  helper / utilities
// ──────────────────────────────────────────────────────────────────────────────
//

func isIpV4(ip net.IP) bool {
	return ip.To4() != nil
}

func isIpV6(ip net.IP) bool {
	return !isIpV4(ip) && ip.To16() != nil
}

func isValidV4Range(start, end net.IP) bool {
	return isIpV4(start) && isIpV4(end) && bytes.Compare(end, start) >= 0
}

func isValidV6Range(start, end net.IP) bool {
	return isIpV6(start) && isIpV6(end) && bytes.Compare(end, start) >= 0
}

func NewRange(start, end net.IP) Range {
	// 正規化
	if s4, e4 := start.To4(), end.To4(); s4 != nil && e4 != nil {
		// defensive copy（スライス再利用対策）
		s4c := append(net.IP(nil), s4...)
		e4c := append(net.IP(nil), e4...)
		if isValidV4Range(s4c, e4c) {
			return &v4Range{start: s4c, end: e4c}
		}
		return nil
	}

	s16, e16 := start.To16(), end.To16()
	if s16 != nil && e16 != nil {
		s16c := append(net.IP(nil), s16...)
		e16c := append(net.IP(nil), e16...)
		if isValidV6Range(s16c, e16c) {
			return &v6Range{start: s16c, end: e16c}
		}
	}
	return nil
}

// ipNetRange は、与えられた *net.IPNet のネットワーク範囲 [first, last] を返します。
// IPv4/IPv6 の両方に対応します（IPv4 は 4 バイトで返す）。
func ipNetRange(n *net.IPNet) (first, last net.IP) {
	ip := n.IP
	// IPv4 は 4 バイト、IPv6 は 16 バイトで処理
	if v4 := ip.To4(); v4 != nil && len(n.Mask) == net.IPv4len {
		first = make(net.IP, net.IPv4len)
		last = make(net.IP, net.IPv4len)
		for i := 0; i < net.IPv4len; i++ {
			first[i] = v4[i] & n.Mask[i]
			last[i] = v4[i] | ^n.Mask[i]
		}
		return first, last
	}

	// IPv6
	ip16 := ip.To16()
	if ip16 == nil || len(n.Mask) != net.IPv6len {
		// マスク長が不一致などの異常系（通常は起きない）
		return nil, nil
	}
	first = make(net.IP, net.IPv6len)
	last = make(net.IP, net.IPv6len)
	for i := 0; i < net.IPv6len; i++ {
		first[i] = ip16[i] & n.Mask[i]
		last[i] = ip16[i] | ^n.Mask[i]
	}
	return first, last
}

//
// ──────────────────────────────────────────────────────────────────────────────
//  Parser utilities
// ──────────────────────────────────────────────────────────────────────────────
//

var (
	reIPAddress  = regexp.MustCompile(`^[0-9a-f.:]+$`)                 // IPv4 and IPv6 address
	reIPRange    = regexp.MustCompile(`^([0-9a-f.:]+)-([0-9a-f.:]+)$`) // IPv4 and IPv6 address range
	reCIDR       = regexp.MustCompile(`^[0-9a-f.:]+/[0-9]{1,3}$`)      // IPv4 and IPv6 CIDR
	reSubnetMask = regexp.MustCompile(`^[0-9.]+/[0-9.]{7,}$`)          // IPv4 subnet mask
)

func parseIPAddress(s string) Range {
	ip := net.ParseIP(s)
	return NewRange(ip, ip)
}

func parseIPRange(s, e string) Range {
	return NewRange(net.ParseIP(s), net.ParseIP(e))
}

func parseCIDR(s string) Range {
	_, network, err := net.ParseCIDR(s)
	if err != nil {
		return nil
	}
	first, last := ipNetRange(network)
	return NewRange(first, last)
}

func parseSubnetMask(s string) Range {
	idx := strings.LastIndexByte(s, '/')
	if idx == -1 {
		return nil
	}

	address, mask := s[:idx], s[idx+1:]

	ip := net.ParseIP(mask).To4()
	if ip == nil {
		return nil
	}

	ones, bits := net.IPv4Mask(ip[0], ip[1], ip[2], ip[3]).Size()
	if ones == 0 && bits == 0 {
		return nil
	}

	return parseCIDR(fmt.Sprintf("%s/%d", address, ones))
}

func ParseRange(s string) (Range, error) {
	s = strings.ToLower(s)

	var r Range
	if m := reIPRange.FindStringSubmatch(s); m != nil {
		start, end := m[1], m[2]
		r = parseIPRange(start, end)
	} else if reIPAddress.MatchString(s) {
		r = parseIPAddress(s)
	} else if reCIDR.MatchString(s) {
		r = parseCIDR(s)
	} else if reSubnetMask.MatchString(s) {
		r = parseSubnetMask(s)
	}

	if r == nil {
		return nil, fmt.Errorf("invalid syntax ip range (%s)", s)
	}

	return r, nil
}

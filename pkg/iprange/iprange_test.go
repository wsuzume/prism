// iprange/iprange_test.go
package iprange

import (
	"net"
	"testing"
)

// --- helpers ---

func mustParse(t *testing.T, s string) Range {
	t.Helper()
	r, err := ParseRange(s)
	if err != nil || r == nil {
		t.Fatalf("ParseRange(%q) failed: %v (r=%v)", s, err, r)
	}
	return r
}

func mustIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("net.ParseIP(%q) = nil", s)
	}
	return ip
}

func assertContains(t *testing.T, r Range, ip string, want bool) {
	t.Helper()
	got := r.Contains(mustIP(t, ip))
	if got != want {
		t.Fatalf("Contains(%s) = %v, want %v", ip, got, want)
	}
}

// --- tests ---

func TestParseIPAddress_V4(t *testing.T) {
	r := mustParse(t, "10.0.0.1")
	if r.Family() != V4Family {
		t.Fatalf("Family = %v, want V4Family", r.Family())
	}
	assertContains(t, r, "10.0.0.1", true)
	assertContains(t, r, "10.0.0.2", false)
}

func TestParseIPAddress_V6(t *testing.T) {
	r := mustParse(t, "::1")
	if r.Family() != V6Family {
		t.Fatalf("Family = %v, want V6Family", r.Family())
	}
	assertContains(t, r, "::1", true)
	assertContains(t, r, "::2", false)
}

func TestParseIPRange_V4(t *testing.T) {
	r := mustParse(t, "10.0.0.1-10.0.0.3")
	if r.Family() != V4Family {
		t.Fatalf("Family = %v, want V4Family", r.Family())
	}
	assertContains(t, r, "10.0.0.0", false)
	assertContains(t, r, "10.0.0.1", true)
	assertContains(t, r, "10.0.0.2", true)
	assertContains(t, r, "10.0.0.3", true)
	assertContains(t, r, "10.0.0.4", false)
}

func TestParseIPRange_V6(t *testing.T) {
	r := mustParse(t, "2001:db8::1-2001:db8::5")
	if r.Family() != V6Family {
		t.Fatalf("Family = %v, want V6Family", r.Family())
	}
	assertContains(t, r, "2001:db8::0", false)
	assertContains(t, r, "2001:db8::1", true)
	assertContains(t, r, "2001:db8::3", true)
	assertContains(t, r, "2001:db8::5", true)
	assertContains(t, r, "2001:db8::6", false)
}

func TestParseCIDR_V4(t *testing.T) {
	// 192.168.1.0/24 -> [192.168.1.0 .. 192.168.1.255]
	r := mustParse(t, "192.168.1.0/24")
	if r.Family() != V4Family {
		t.Fatalf("Family = %v, want V4Family", r.Family())
	}
	assertContains(t, r, "192.168.1.0", true)   // network
	assertContains(t, r, "192.168.1.255", true) // broadcast
	assertContains(t, r, "192.168.0.255", false)
	assertContains(t, r, "192.168.2.0", false)
}

func TestParseCIDR_V6(t *testing.T) {
	// 2001:db8::/126 -> [:: .. ::3]
	r := mustParse(t, "2001:db8::/126")
	if r.Family() != V6Family {
		t.Fatalf("Family = %v, want V6Family", r.Family())
	}
	assertContains(t, r, "2001:db8::", true)
	assertContains(t, r, "2001:db8::1", true)
	assertContains(t, r, "2001:db8::2", true)
	assertContains(t, r, "2001:db8::3", true)
	assertContains(t, r, "2001:db8::4", false)
}

func TestParseSubnetMask_V4(t *testing.T) {
	// 255.255.255.0 -> /24 と同等
	r := mustParse(t, "192.168.10.0/255.255.255.0")
	if r.Family() != V4Family {
		t.Fatalf("Family = %v, want V4Family", r.Family())
	}
	assertContains(t, r, "192.168.10.0", true)
	assertContains(t, r, "192.168.10.128", true)
	assertContains(t, r, "192.168.10.255", true)
	assertContains(t, r, "192.168.11.0", false)
}

func TestParseIPv6UppercaseHex_IsAccepted(t *testing.T) {
	// 入力を小文字化しているため、大文字混在 IPv6 も受理されるはず
	r := mustParse(t, "2001:DB8::1/127")
	if r.Family() != V6Family {
		t.Fatalf("Family = %v, want V6Family", r.Family())
	}
	assertContains(t, r, "2001:db8::1", true)
	assertContains(t, r, "2001:db8::0", true)
	assertContains(t, r, "2001:db8::2", false)
}

func TestNewRange_InvalidOrder_ReturnsNil(t *testing.T) {
	start := net.ParseIP("10.0.0.10")
	end := net.ParseIP("10.0.0.1")
	if got := NewRange(start, end); got != nil {
		t.Fatalf("NewRange(start>end) = %v; want nil", got)
	}
}

func TestParseRange_InvalidInputs(t *testing.T) {
	bad := []string{
		"",                         // empty
		"not-an-ip",                // garbage
		"300.0.0.1",                // invalid v4
		"1.2.3.4/33",               // invalid v4 prefix
		"1.2.3.4/255.0.0",          // bad mask
		"1.2.3.4-1.2.3",            // malformed range
		"2001:db8::/129",           // invalid v6 prefix
		"2001:db8:::1-2001:db8::2", // invalid v6 (triple colon)
		"2001:db8::g-2001:db8::1",  // invalid v6 (non-hex 'g')
		"10.0.0.1-2001:db8::1",     // mixed family (v4-v6)
	}
	for _, s := range bad {
		if r, err := ParseRange(s); err == nil || r != nil {
			t.Fatalf("ParseRange(%q) = (%v, %v); want (error, nil range)", s, r, err)
		}
	}
}

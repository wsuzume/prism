package iprange

import (
	"net"
)

type Range struct {
	start net.IP
	end   net.IP
}

func (r *Range) Contains(ip net.IP) bool {
    if bytes.Compare(ip, r.start) >= 0 && bytes.Compare(ip, r.end) <= 0 {
        return true
    }
    return false
}
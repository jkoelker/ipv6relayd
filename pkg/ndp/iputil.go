package ndp

import (
	"net"
	"net/netip"
)

// ipToKey renders an IPv6 address into the string key used by caches/routes.
func ipToKey(ip net.IP) (string, bool) {
	addr, ok := netipAddrFromIP(ip)
	if !ok {
		return "", false
	}

	return addr.String(), true
}

func netipAddrFromIP(ipAddr net.IP) (netip.Addr, bool) {
	if ipAddr == nil {
		return netip.Addr{}, false
	}

	addr, ok := netip.AddrFromSlice(ipAddr.To16())
	if !ok {
		return netip.Addr{}, false
	}

	return addr, true
}

func netipAddrToIP(addr netip.Addr) net.IP {
	if !addr.Is6() {
		return nil
	}

	ipAddr := make(net.IP, net.IPv6len)
	bytes := addr.As16()
	copy(ipAddr, bytes[:])

	return ipAddr
}

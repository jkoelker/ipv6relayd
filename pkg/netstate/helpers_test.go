package netstate_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func mustCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(cidr)
	require.NoErrorf(t, err, "parse cidr %s", cidr)

	return ipNet
}

func mustIPv6(t *testing.T, addr string) net.IP {
	t.Helper()
	ip := net.ParseIP(addr)
	require.NotNilf(t, ip, "parse ipv6 %s", addr)
	require.NotNilf(t, ip.To16(), "parse ipv6 %s", addr)

	return ip
}

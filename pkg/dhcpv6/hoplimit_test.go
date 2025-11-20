package dhcpv6_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jkoelker/ipv6relayd/pkg/dhcpv6"
)

func TestHopLimitForMulticastLocalScope(t *testing.T) {
	t.Parallel()

	dst := &net.UDPAddr{IP: net.ParseIP("ff02::1:2")}

	require.Equal(t, dhcpv6.MulticastRelayHopLimit, dhcpv6.HopLimitForDestination(dst))
}

func TestHopLimitForMulticastSiteScope(t *testing.T) {
	t.Parallel()

	dst := &net.UDPAddr{IP: net.ParseIP("ff05::1:3")}

	require.Equal(t, dhcpv6.MulticastRelayHopLimit, dhcpv6.HopLimitForDestination(dst))
}

func TestHopLimitForUnicast(t *testing.T) {
	t.Parallel()

	dst := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: dhcpv6.ServerPort}

	require.Equal(t, dhcpv6.DefaultHopLimit, dhcpv6.HopLimitForDestination(dst))
}

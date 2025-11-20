package dhcpv6

import (
	"net"
	"testing"

	dhcpv6 "github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/require"
)

func TestDownstreamControlMessageUsesMulticastHopLimit(t *testing.T) {
	t.Parallel()

	ifc := &net.Interface{Index: 10, Name: "lan"}
	dst := &net.UDPAddr{IP: net.ParseIP("ff02::1:2"), Port: ClientPort}

	cm := downstreamControlMessage(ifc, dst)

	require.Equal(t, ifc.Index, cm.IfIndex, "control message should target downstream interface")
	require.Equal(t, MulticastRelayHopLimit, cm.HopLimit, "multicast replies must use hop-limit 8")
}

func TestDownstreamDestinationRejectsMissingPeer(t *testing.T) {
	t.Parallel()

	relay := &dhcpv6.RelayMessage{
		PeerAddr: net.IPv6zero,
	}

	addr, err := downstreamDestination(relay, ClientPort)
	require.Nil(t, addr)
	require.ErrorIs(t, err, ErrMissingPeerAddress)
}

func TestDownstreamDestinationReturnsPeer(t *testing.T) {
	t.Parallel()

	ip := net.ParseIP("fe80::1234")
	relay := &dhcpv6.RelayMessage{
		PeerAddr: ip,
	}

	addr, err := downstreamDestination(relay, ClientPort)
	require.NoError(t, err)
	require.Equal(t, ip, addr.IP)
	require.Equal(t, ClientPort, addr.Port)
}

package dhcpv6_test

import (
	"net"
	"testing"

	dhcpv6msg "github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/require"

	"github.com/jkoelker/ipv6relayd/pkg/dhcpv6"
)

func TestRelayForwardIncrementsHopCount(t *testing.T) {
	t.Parallel()

	inner := &dhcpv6msg.RelayMessage{
		MessageType: dhcpv6msg.MessageTypeRelayForward,
		HopCount:    5,
		LinkAddr:    net.ParseIP("fe80::1"),
		PeerAddr:    net.ParseIP("fe80::2"),
	}

	svc := newTestService(t)

	relay, err := svc.BuildRelayForward(
		inner,
		net.ParseIP("fe80::1"),
		net.ParseIP("fe80::2"),
		&net.Interface{Name: "lan"},
	)
	require.NoError(t, err)
	require.Equal(t, uint8(6), relay.HopCount, "hop-count should increment before forwarding")
}

func TestRelayForwardMaxHopCountNotDroppedInitially(t *testing.T) {
	t.Parallel()

	inner := &dhcpv6msg.RelayMessage{
		MessageType: dhcpv6msg.MessageTypeRelayForward,
		HopCount:    dhcpv6.MaxHopCount - 1,
		LinkAddr:    net.ParseIP("fe80::3"),
		PeerAddr:    net.ParseIP("fe80::4"),
	}

	svc := newTestService(t)

	relay, err := svc.BuildRelayForward(
		inner,
		net.ParseIP("fe80::3"),
		net.ParseIP("fe80::4"),
		&net.Interface{Name: "lan"},
	)
	require.NoError(t, err)
	require.EqualValues(
		t,
		dhcpv6.MaxHopCount,
		relay.HopCount,
		"hop-count should reach the RFC limit when incremented",
	)
}

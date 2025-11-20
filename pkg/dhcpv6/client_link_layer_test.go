package dhcpv6_test

import (
	"net"
	"testing"

	dhcpv6msg "github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRelayForwardAddsClientLinkLayerForClientMessages(t *testing.T) {
	t.Parallel()

	mac, err := net.ParseMAC("02:00:5e:00:53:23")
	require.NoError(t, err)

	duid := &dhcpv6msg.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: mac}
	msg, err := dhcpv6msg.NewMessage()
	require.NoError(t, err)
	msg.MessageType = dhcpv6msg.MessageTypeSolicit
	msg.Options.Add(dhcpv6msg.OptClientID(duid))

	svc := newTestService(t)
	relay, err := svc.BuildRelayForward(
		msg,
		net.ParseIP("2001:db8::1"),
		net.ParseIP("fe80::1"),
		&net.Interface{Name: "lan"},
	)
	require.NoError(t, err)

	gotType, gotHW := relay.Options.ClientLinkLayerAddress()
	require.NotNil(t, gotHW, "should attach client link-layer address on first-hop")
	assert.Equal(t, iana.HWTypeEthernet, gotType)
	assert.Equal(t, mac, gotHW)
}

func TestRelayForwardSkipsClientLinkLayerWhenRelayingRelayForward(t *testing.T) {
	t.Parallel()

	inner := &dhcpv6msg.RelayMessage{
		MessageType: dhcpv6msg.MessageTypeRelayForward,
		HopCount:    1,
		LinkAddr:    net.ParseIP("2001:db8::2"),
		PeerAddr:    net.ParseIP("fe80::2"),
	}

	svc := newTestService(t)
	relay, err := svc.BuildRelayForward(
		inner,
		net.ParseIP("2001:db8::3"),
		net.ParseIP("fe80::3"),
		&net.Interface{Name: "lan"},
	)
	require.NoError(t, err)

	_, gotHW := relay.Options.ClientLinkLayerAddress()
	assert.Nil(t, gotHW, "must not add client link-layer option when relaying relay-forward")
}

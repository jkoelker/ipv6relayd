package dhcpv6_test

import (
	"net"
	"testing"
	"time"

	dhcpv6msg "github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/require"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/dhcpv6"
)

// RFC 8415 requires relays not to modify DHCP messages; ensure we leave replies intact.
func TestPrepareDownstreamPayloadDoesNotRewriteReply(t *testing.T) {
	t.Parallel()

	msg, err := dhcpv6msg.NewMessage()
	require.NoError(t, err)
	msg.MessageType = dhcpv6msg.MessageTypeReply
	// Populate with a DNS option to detect unintended rewrites.
	msg.Options.Add(dhcpv6msg.OptDNS(net.ParseIP("2001:db8::1")))

	original := msg.ToBytes()

	svc := newTestService(t)
	raw, _, _, err := svc.PrepareDownstreamPayload(msg)
	require.NoError(t, err)
	require.Equal(t, original, raw, "relay should forward DHCPv6 reply without mutation")
}

func TestPrepareDownstreamPayloadPreservesIAPrefixLifetimes(t *testing.T) {
	t.Parallel()

	msg, err := dhcpv6msg.NewMessage()
	require.NoError(t, err)
	msg.MessageType = dhcpv6msg.MessageTypeReply

	ia := &dhcpv6msg.OptIAPD{}
	prefix := &dhcpv6msg.OptIAPrefix{PreferredLifetime: 7200 * time.Second, ValidLifetime: 14400 * time.Second}
	ia.Options.Add(prefix)
	msg.Options.Add(ia)

	original := msg.ToBytes()

	svc := newTestService(t)
	raw, _, _, err := svc.PrepareDownstreamPayload(msg)
	require.NoError(t, err)

	forwarded, err := dhcpv6msg.FromBytes(raw)
	require.NoError(t, err)

	relayReply, ok := forwarded.(*dhcpv6msg.Message)
	require.True(t, ok, "expected message reply")
	gotPD := relayReply.Options.GetOne(dhcpv6msg.OptionIAPD)
	require.NotNil(t, gotPD)

	decoded, ok := gotPD.(*dhcpv6msg.OptIAPD)
	require.True(t, ok)
	inner := decoded.Options.GetOne(dhcpv6msg.OptionIAPrefix)
	require.NotNil(t, inner)

	decodedPrefix, ok := inner.(*dhcpv6msg.OptIAPrefix)
	require.True(t, ok)
	require.Equal(t, prefix.PreferredLifetime, decodedPrefix.PreferredLifetime)
	require.Equal(t, prefix.ValidLifetime, decodedPrefix.ValidLifetime)
	require.Equal(t, original, raw, "relay should not alter IA_PD lifetimes")
}

func TestPrepareDownstreamPayloadRewritesDNSWhenConfigured(t *testing.T) {
	t.Parallel()

	msg, err := dhcpv6msg.NewMessage()
	require.NoError(t, err)
	msg.MessageType = dhcpv6msg.MessageTypeReply

	svc := newTestService(
		t,
		dhcpv6.WithConfig(config.DHCPv6Config{Upstream: "[2001:db8::1]:547", ForceReplyDNSRewrite: true}),
		dhcpv6.WithDNSOverride([]net.IP{net.ParseIP("2001:db8::53")}),
	)

	raw, _, _, err := svc.PrepareDownstreamPayload(msg)
	require.NoError(t, err)

	forwarded, err := dhcpv6msg.FromBytes(raw)
	require.NoError(t, err)

	reply, ok := forwarded.(*dhcpv6msg.Message)
	require.True(t, ok)
	dns := reply.Options.GetOne(dhcpv6msg.OptionDNSRecursiveNameServer)
	require.NotNil(t, dns)

	found := false
	wanted := net.ParseIP("2001:db8::53").To16()
	for b := dns.ToBytes(); len(b) >= net.IPv6len; b = b[net.IPv6len:] {
		if net.IP(b[:net.IPv6len]).Equal(wanted) {
			found = true

			break
		}
	}
	require.True(t, found, "dns override missing wanted address")
}

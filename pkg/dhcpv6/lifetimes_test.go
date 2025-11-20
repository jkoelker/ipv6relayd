package dhcpv6_test

import (
	"net"
	"testing"
	"time"

	insdhcpv6 "github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/require"

	"github.com/jkoelker/ipv6relayd/pkg/dhcpv6"
)

func TestClampIAPrefixLifetimes(t *testing.T) {
	t.Parallel()

	prefix := &insdhcpv6.OptIAPrefix{
		PreferredLifetime: 12 * time.Hour,
		ValidLifetime:     24 * time.Hour,
		Prefix: &net.IPNet{
			IP:   net.ParseIP("2001:db8:1::"),
			Mask: net.CIDRMask(64, 128),
		},
	}

	ia := &insdhcpv6.OptIAPD{}
	ia.Options.Add(prefix)

	msg, err := insdhcpv6.NewMessage()
	require.NoError(t, err)
	msg.Options.Add(ia)

	dhcpv6.ClampIAPrefixLifetimes(msg)

	require.LessOrEqual(t, prefix.ValidLifetime, dhcpv6.NDValidLimit)
	require.LessOrEqual(t, prefix.PreferredLifetime, dhcpv6.NDPreferredLimit)
	require.LessOrEqual(t, prefix.PreferredLifetime, prefix.ValidLifetime)
}

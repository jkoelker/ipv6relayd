package dhcpv6_test

import (
	"net"
	"testing"

	insdhcpv6 "github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/require"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/dhcpv6"
)

// When link-address is unspecified, the relay must include Interface-ID even if
// injection is disabled in config (RFC 8415 §19.1.1/19.1.2).
func TestBuildRelayForwardAddsInterfaceIDWhenLinkAddrUnspecified(t *testing.T) {
	t.Parallel()

	svc := newTestService(
		t,
		dhcpv6.WithConfig(config.DHCPv6Config{Upstream: "[2001:db8::1]:547", InjectInterface: config.BoolPtr(false)}),
	)

	msg, err := insdhcpv6.NewMessage()
	require.NoError(t, err)

	iface := &net.Interface{Name: "lan"}
	relay, err := svc.BuildRelayForward(msg, net.IPv6zero, net.ParseIP("2001:db8::1"), iface)
	require.NoError(t, err)

	require.Equal(t, []byte("lan"), relay.Options.InterfaceID(), "interface-id must be added when link-address is ::")
}

// When link-address is link-local, the relay must still include Interface-ID to
// disambiguate the incoming link even if injection is disabled.
func TestBuildRelayForwardAddsInterfaceIDWhenLinkAddrLinkLocal(t *testing.T) {
	t.Parallel()

	svc := newTestService(
		t,
		dhcpv6.WithConfig(config.DHCPv6Config{Upstream: "[2001:db8::1]:547", InjectInterface: config.BoolPtr(false)}),
	)

	msg, err := insdhcpv6.NewMessage()
	require.NoError(t, err)

	iface := &net.Interface{Name: "lan"}
	linkLocal := net.ParseIP("fe80::1")
	relay, err := svc.BuildRelayForward(
		msg,
		linkLocal,
		net.ParseIP("2001:db8::1"),
		iface,
	)
	require.NoError(t, err)

	require.Equal(t, []byte("lan"), relay.Options.InterfaceID(),
		"interface-id must be added when link-address is link-local")
}

// When link-address is global/ULA and interface-id injection is disabled, the
// relay should respect the config and omit Interface-ID.
func TestBuildRelayForwardSkipsInterfaceIDWhenGlobalAndDisabled(t *testing.T) {
	t.Parallel()

	svc := newTestService(
		t,
		dhcpv6.WithConfig(config.DHCPv6Config{Upstream: "[2001:db8::1]:547", InjectInterface: config.BoolPtr(false)}),
	)

	msg, err := insdhcpv6.NewMessage()
	require.NoError(t, err)

	iface := &net.Interface{Name: "lan"}
	gua := net.ParseIP("2001:db8::1")
	relay, err := svc.BuildRelayForward(
		msg,
		gua,
		net.ParseIP("2001:db8::2"),
		iface,
	)
	require.NoError(t, err)

	require.Empty(t, relay.Options.InterfaceID(),
		"interface-id should be omitted when link-address is global and injection disabled")
}

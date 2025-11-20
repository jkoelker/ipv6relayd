package dhcpv6_test

import (
	"net"
	"testing"

	insdhcpv6 "github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/require"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/dhcpv6"
	"github.com/jkoelker/ipv6relayd/pkg/iface"
	"github.com/jkoelker/ipv6relayd/pkg/netstate"
	"github.com/jkoelker/ipv6relayd/pkg/testutil"
)

// When Interface-ID injection is enabled (default), a relay must keep a
// link-local link-address for client-originated traffic per RFC 8415 §19.1.1.
func TestLinkAddressWithInterfaceIDPreservesLinkLocal(t *testing.T) {
	t.Parallel()

	linkLocal := net.ParseIP("fe80::1234")
	peer := net.ParseIP("fe80::abcd")

	mgr := iface.NewManager()
	mgr.Inject("wan", &net.Interface{Name: "wan", Index: 1})
	mgr.Inject("lan", &net.Interface{Name: "lan", Index: 2})

	linkLocals, err := netstate.NewLink(
		config.InterfaceConfig{IfName: "wan"},
		[]config.InterfaceConfig{{IfName: "lan", LinkLocal: linkLocal.String()}},
	)
	require.NoError(t, err)

	events, cancel := newTestInterfaceEvents()
	svc, err := dhcpv6.New(
		config.InterfaceConfig{IfName: "wan"},
		[]config.InterfaceConfig{{IfName: "lan"}},
		config.DHCPv6Config{Upstream: "[2001:db8::1]:547"},
		mgr,
		dhcpv6.WithLinkLocals(linkLocals),
		dhcpv6.WithLogger(testutil.LoggerFromTB(t)),
		dhcpv6.WithInterfaceEvents(events, cancel),
	)
	require.NoError(t, err)

	downstreamIface := &net.Interface{Name: "lan"}
	addr, err := svc.LinkAddressForRelay(
		downstreamIface,
		config.InterfaceConfig{IfName: "lan"},
		nil,
		peer,
		&insdhcpv6.Message{},
	)
	require.NoError(t, err)
	require.True(t, linkLocal.Equal(addr), "link-local link-address should be preserved when peer is link-local")
}

// When a client-originated message arrives with a global/ULA source, we must
// still forward a concrete link-address instead of zeroing it.
func TestLinkAddressWithInterfaceIDPreservesGlobalForClient(t *testing.T) {
	t.Parallel()

	peer := net.ParseIP("2001:db8::1")
	selected := net.ParseIP("fd00::1")

	mgr := iface.NewManager()
	mgr.Inject("wan", &net.Interface{Name: "wan", Index: 1})
	mgr.Inject("lan", &net.Interface{Name: "lan", Index: 2})

	linkLocals, err := netstate.NewLink(
		config.InterfaceConfig{IfName: "wan"},
		[]config.InterfaceConfig{{IfName: "lan", LinkLocal: selected.String()}},
	)
	require.NoError(t, err)

	events2, cancel2 := newTestInterfaceEvents()
	svc, err := dhcpv6.New(
		config.InterfaceConfig{IfName: "wan"},
		[]config.InterfaceConfig{{IfName: "lan"}},
		config.DHCPv6Config{Upstream: "[2001:db8::1]:547"},
		mgr,
		dhcpv6.WithLinkLocals(linkLocals),
		dhcpv6.WithLogger(testutil.LoggerFromTB(t)),
		dhcpv6.WithInterfaceEvents(events2, cancel2),
	)
	require.NoError(t, err)

	downstreamIface := &net.Interface{Name: "lan"}
	addr, err := svc.LinkAddressForRelay(
		downstreamIface,
		config.InterfaceConfig{IfName: "lan"},
		nil,
		peer,
		&insdhcpv6.Message{},
	)
	require.NoError(t, err)
	require.True(t, selected.Equal(addr), "global/ULA link-address should be preserved for client traffic")
}

// When relaying a Relay-forward with a global source, RFC 8415 §19.1.2 requires
// link-address to be set to ::.
func TestLinkAddressZeroedForRelayForwardWithGlobalPeer(t *testing.T) {
	t.Parallel()

	peer := net.ParseIP("2001:db8::2")
	selected := net.ParseIP("fd00::1")

	mgr := iface.NewManager()
	mgr.Inject("wan", &net.Interface{Name: "wan", Index: 1})
	mgr.Inject("lan", &net.Interface{Name: "lan", Index: 2})

	linkLocals, err := netstate.NewLink(
		config.InterfaceConfig{IfName: "wan"},
		[]config.InterfaceConfig{{IfName: "lan", LinkLocal: selected.String()}},
	)
	require.NoError(t, err)

	events3, cancel3 := newTestInterfaceEvents()
	svc, err := dhcpv6.New(
		config.InterfaceConfig{IfName: "wan"},
		[]config.InterfaceConfig{{IfName: "lan"}},
		config.DHCPv6Config{Upstream: "[2001:db8::1]:547"},
		mgr,
		dhcpv6.WithLinkLocals(linkLocals),
		dhcpv6.WithLogger(testutil.LoggerFromTB(t)),
		dhcpv6.WithInterfaceEvents(events3, cancel3),
	)
	require.NoError(t, err)

	downstreamIface := &net.Interface{Name: "lan"}
	addr, err := svc.LinkAddressForRelay(
		downstreamIface,
		config.InterfaceConfig{IfName: "lan"},
		nil,
		peer,
		&insdhcpv6.RelayMessage{},
	)
	require.NoError(t, err)
	require.True(t, net.IPv6zero.Equal(addr), "relay-forward with global peer must zero link-address")
}

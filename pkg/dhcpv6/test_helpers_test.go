package dhcpv6_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/dhcpv6"
	"github.com/jkoelker/ipv6relayd/pkg/iface"
	"github.com/jkoelker/ipv6relayd/pkg/ifmon"
	"github.com/jkoelker/ipv6relayd/pkg/testutil"
)

func newTestInterfaceEvents() (<-chan ifmon.InterfaceEvent, func()) {
	ch := make(chan ifmon.InterfaceEvent)
	close(ch)

	return ch, func() {}
}

func newTestService(t *testing.T, opts ...func(*dhcpv6.Options)) *dhcpv6.Service {
	t.Helper()

	events, cancel := newTestInterfaceEvents()
	mgr := iface.NewManager()
	mgr.Inject("wan", &net.Interface{Name: "wan", Index: 1})
	mgr.Inject("lan0", &net.Interface{Name: "lan0", Index: 2})

	baseOpts := []func(*dhcpv6.Options){
		dhcpv6.WithLogger(testutil.LoggerFromTB(t)),
		dhcpv6.WithInterfaceEvents(events, cancel),
		dhcpv6.WithInterfaceAddrs(func(_ *net.Interface) ([]net.Addr, error) {
			return []net.Addr{
					&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
				},
				nil
		}),
		dhcpv6.WithUpstream(&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: dhcpv6.ServerPort}),
	}
	baseOpts = append(baseOpts, opts...)

	svc, err := dhcpv6.New(
		config.InterfaceConfig{IfName: "wan"},
		[]config.InterfaceConfig{{IfName: "lan0"}},
		config.DHCPv6Config{Upstream: "[2001:db8::1]:547"},
		mgr,
		baseOpts...,
	)
	require.NoError(t, err)

	return svc
}

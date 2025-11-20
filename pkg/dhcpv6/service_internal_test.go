package dhcpv6

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/iface"
	"github.com/jkoelker/ipv6relayd/pkg/ifmon"
)

func newInternalInterfaceEvents(t *testing.T) (<-chan ifmon.InterfaceEvent, func()) {
	t.Helper()

	ch := make(chan ifmon.InterfaceEvent)
	close(ch)

	return ch, func() {}
}

type fakeUpstreamResolver struct {
	addrs        []*net.UDPAddr
	autodiscover bool
	calls        int
}

type errorUpstreamResolver struct {
	err error
}

func (f *fakeUpstreamResolver) Resolve(
	_ config.InterfaceConfig,
	_ config.DHCPv6Config,
	_ *iface.Manager,
) (*net.UDPAddr, bool, error) {
	if len(f.addrs) == 0 {
		return nil, f.autodiscover, nil
	}

	idx := f.calls
	if idx >= len(f.addrs) {
		idx = len(f.addrs) - 1
	}

	f.calls++

	return cloneUDPAddr(f.addrs[idx]), f.autodiscover, nil
}

func (e *errorUpstreamResolver) Resolve(
	_ config.InterfaceConfig,
	_ config.DHCPv6Config,
	_ *iface.Manager,
) (*net.UDPAddr, bool, error) {
	return nil, true, e.err
}

func TestRefreshUpstreamUpdatesAutoDiscoveredAddress(t *testing.T) {
	t.Parallel()

	mgr := iface.NewManager()
	mgr.Inject("wan", &net.Interface{Name: "wan", Index: 1})

	resolver := &fakeUpstreamResolver{
		addrs: []*net.UDPAddr{
			{IP: net.ParseIP("fe80::1"), Zone: "wan", Port: serverPort},
			{IP: net.ParseIP("fe80::2"), Zone: "wan", Port: serverPort},
		},
		autodiscover: true,
	}

	events, cancel := newInternalInterfaceEvents(t)
	svc, err := New(
		config.InterfaceConfig{IfName: "wan"},
		nil,
		config.DHCPv6Config{},
		mgr,
		WithUpstreamResolver(resolver.Resolve),
		WithInterfaceEvents(events, cancel),
	)
	require.NoError(t, err)

	initial := svc.currentUpstream()
	require.NotNil(t, initial)
	assert.True(t, initial.IP.Equal(net.ParseIP("fe80::1")))

	require.NoError(t, svc.refreshUpstream("link update"))

	assert.Equal(t, 2, resolver.calls)

	updated := svc.currentUpstream()
	require.NotNil(t, updated)
	assert.True(t, updated.IP.Equal(net.ParseIP("fe80::2")))
}

func TestRefreshUpstreamSkipsWhenNotAutodiscovered(t *testing.T) {
	t.Parallel()

	mgr := iface.NewManager()
	mgr.Inject("wan", &net.Interface{Name: "wan", Index: 2})

	resolver := &fakeUpstreamResolver{
		addrs:        []*net.UDPAddr{{IP: net.ParseIP("2001:db8::1"), Port: serverPort}},
		autodiscover: false,
	}

	cfg := config.DHCPv6Config{Upstream: "[2001:db8::1]:547"}

	events2, cancel2 := newInternalInterfaceEvents(t)
	svc, err := New(
		config.InterfaceConfig{IfName: "wan"},
		nil,
		cfg,
		mgr,
		WithUpstreamResolver(resolver.Resolve),
		WithInterfaceEvents(events2, cancel2),
	)
	require.NoError(t, err)

	assert.False(t, svc.autoDiscoverUpstream, "expected autoDiscoverUpstream to be false")

	require.NoError(t, svc.refreshUpstream("link update"))

	assert.Equal(t, 1, resolver.calls)
}

func TestEnsureUpstreamFallsBackToMulticastWhenNoGateway(t *testing.T) {
	t.Parallel()

	mgr := iface.NewManager()
	mgr.Inject("wan", &net.Interface{Name: "wan", Index: 4})

	resolver := &errorUpstreamResolver{err: ErrNoIPv6Gateway}

	events3, cancel3 := newInternalInterfaceEvents(t)
	svc, err := New(
		config.InterfaceConfig{IfName: "wan"},
		nil,
		config.DHCPv6Config{},
		mgr,
		WithUpstreamResolver(resolver.Resolve),
		WithInterfaceEvents(events3, cancel3),
	)
	require.NoError(t, err)

	upstream := svc.currentUpstream()
	require.NotNil(t, upstream)
	require.True(t, upstream.IP.IsMulticast())
	require.Equal(t, "wan", upstream.Zone)
	require.Equal(t, serverPort, upstream.Port)
}

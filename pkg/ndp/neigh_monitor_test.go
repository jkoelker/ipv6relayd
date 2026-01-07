//nolint:testpackage // testing unexported handleNeighborUpdate
package ndp

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/iface"
	"github.com/jkoelker/ipv6relayd/pkg/ifmon"
)

func newTestServiceForNeighMonitor(t *testing.T) (*Service, *net.Interface, *net.Interface) {
	t.Helper()

	upstreamIface := &net.Interface{Index: 1, Name: "wan"}
	downstreamIface := &net.Interface{Index: 2, Name: "home"}

	ifaceMgr := iface.NewManager()
	ifaceMgr.Inject("wan", upstreamIface)
	ifaceMgr.Inject("home", downstreamIface)

	eventCh := make(chan ifmon.InterfaceEvent, 1)

	svc, err := New(
		config.InterfaceConfig{IfName: "wan"},
		[]config.InterfaceConfig{{IfName: "home"}},
		config.NDPConfig{Mode: "relay"},
		ifaceMgr,
		WithInterfaceEvents(eventCh, func() {}),
	)
	assert.NoError(t, err)

	return svc, upstreamIface, downstreamIface
}

func TestHandleNeighborUpdate_IgnoresNonUpstreamInterface(t *testing.T) {
	t.Parallel()

	svc, upstreamIface, downstreamIface := newTestServiceForNeighMonitor(t)

	update := netlink.NeighUpdate{
		Type: unix.RTM_NEWNEIGH,
		Neigh: netlink.Neigh{
			LinkIndex: 99,
			Family:    unix.AF_INET6,
			State:     netlink.NUD_FAILED,
			IP:        net.ParseIP("2001:db8::1"),
		},
	}

	svc.handleNeighborUpdate(update, upstreamIface.Index, []*net.Interface{downstreamIface})

	_, found := svc.lookupTargetInterface(net.ParseIP("2001:db8::1"))
	assert.False(t, found)
}

func TestHandleNeighborUpdate_IgnoresIPv4(t *testing.T) {
	t.Parallel()

	svc, upstreamIface, downstreamIface := newTestServiceForNeighMonitor(t)

	update := netlink.NeighUpdate{
		Type: unix.RTM_NEWNEIGH,
		Neigh: netlink.Neigh{
			LinkIndex: upstreamIface.Index,
			Family:    unix.AF_INET,
			State:     netlink.NUD_FAILED,
			IP:        net.ParseIP("192.168.1.1"),
		},
	}

	svc.handleNeighborUpdate(update, upstreamIface.Index, []*net.Interface{downstreamIface})

	_, found := svc.lookupTargetInterface(net.ParseIP("192.168.1.1"))
	assert.False(t, found)
}

func TestHandleNeighborUpdate_IgnoresReachableState(t *testing.T) {
	t.Parallel()

	svc, upstreamIface, downstreamIface := newTestServiceForNeighMonitor(t)

	update := netlink.NeighUpdate{
		Type: unix.RTM_NEWNEIGH,
		Neigh: netlink.Neigh{
			LinkIndex: upstreamIface.Index,
			Family:    unix.AF_INET6,
			State:     netlink.NUD_REACHABLE,
			IP:        net.ParseIP("2001:db8::1"),
		},
	}

	svc.handleNeighborUpdate(update, upstreamIface.Index, []*net.Interface{downstreamIface})

	_, found := svc.lookupTargetInterface(net.ParseIP("2001:db8::1"))
	assert.False(t, found)
}

func TestHandleNeighborUpdate_IgnoresLinkLocalAddress(t *testing.T) {
	t.Parallel()

	svc, upstreamIface, downstreamIface := newTestServiceForNeighMonitor(t)

	update := netlink.NeighUpdate{
		Type: unix.RTM_NEWNEIGH,
		Neigh: netlink.Neigh{
			LinkIndex: upstreamIface.Index,
			Family:    unix.AF_INET6,
			State:     netlink.NUD_FAILED,
			IP:        net.ParseIP("fe80::1"),
		},
	}

	svc.handleNeighborUpdate(update, upstreamIface.Index, []*net.Interface{downstreamIface})

	_, found := svc.lookupTargetInterface(net.ParseIP("fe80::1"))
	assert.False(t, found)
}

func TestHandleNeighborUpdate_TracksFailedGlobalUnicast(t *testing.T) {
	t.Parallel()

	svc, upstreamIface, downstreamIface := newTestServiceForNeighMonitor(t)

	targetIP := net.ParseIP("2001:db8::1")
	update := netlink.NeighUpdate{
		Type: unix.RTM_NEWNEIGH,
		Neigh: netlink.Neigh{
			LinkIndex: upstreamIface.Index,
			Family:    unix.AF_INET6,
			State:     netlink.NUD_FAILED,
			IP:        targetIP,
		},
	}

	svc.handleNeighborUpdate(update, upstreamIface.Index, []*net.Interface{downstreamIface})

	ifc, found := svc.lookupTargetInterface(targetIP)
	assert.True(t, found)
	assert.Equal(t, downstreamIface.Name, ifc.Name)
}

func TestHandleNeighborUpdate_TracksIncompleteGlobalUnicast(t *testing.T) {
	t.Parallel()

	svc, upstreamIface, downstreamIface := newTestServiceForNeighMonitor(t)

	targetIP := net.ParseIP("2001:db8::2")
	update := netlink.NeighUpdate{
		Type: unix.RTM_NEWNEIGH,
		Neigh: netlink.Neigh{
			LinkIndex: upstreamIface.Index,
			Family:    unix.AF_INET6,
			State:     netlink.NUD_INCOMPLETE,
			IP:        targetIP,
		},
	}

	svc.handleNeighborUpdate(update, upstreamIface.Index, []*net.Interface{downstreamIface})

	ifc, found := svc.lookupTargetInterface(targetIP)
	assert.True(t, found)
	assert.Equal(t, downstreamIface.Name, ifc.Name)
}

func TestIsFailedOrIncomplete(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		state    int
		expected bool
	}{
		{"FAILED", netlink.NUD_FAILED, true},
		{"INCOMPLETE", netlink.NUD_INCOMPLETE, true},
		{"REACHABLE", netlink.NUD_REACHABLE, false},
		{"STALE", netlink.NUD_STALE, false},
		{"DELAY", netlink.NUD_DELAY, false},
		{"PROBE", netlink.NUD_PROBE, false},
		{"PERMANENT", netlink.NUD_PERMANENT, false},
		{"NOARP", netlink.NUD_NOARP, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, isFailedOrIncomplete(tc.state))
		})
	}
}

func TestNeighStateString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state    int
		expected string
	}{
		{netlink.NUD_FAILED, "FAILED"},
		{netlink.NUD_INCOMPLETE, "INCOMPLETE"},
		{netlink.NUD_REACHABLE, "REACHABLE"},
		{netlink.NUD_STALE, "STALE"},
		{netlink.NUD_DELAY, "DELAY"},
		{netlink.NUD_PROBE, "PROBE"},
		{netlink.NUD_PERMANENT, "PERMANENT"},
		{netlink.NUD_NOARP, "NOARP"},
		{0, "UNKNOWN"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, neighStateString(tc.state))
		})
	}
}

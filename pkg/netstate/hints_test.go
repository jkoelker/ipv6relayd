package netstate_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jkoelker/ipv6relayd/pkg/netstate"
)

const (
	hintsLinkLocal = "fe80::1"
)

func TestHintsCaptureStringsFilters(t *testing.T) {
	t.Parallel()

	hintsStore := netstate.NewHints(netstate.WithHintsFilter(func(ip net.IP) bool {
		return ip.IsLinkLocalUnicast()
	}))

	hintsStore.CaptureStrings("eth0", []string{hintsLinkLocal, "not-an-ip", "2001:db8::1"})
	assert.True(t, hintsStore.Has("eth0"))

	got := hintsStore.Hints("eth0")
	assert.Len(t, got, 1)
	assert.Equal(t, hintsLinkLocal, got[0].String())
}

func TestHintsStoreAndHintsClone(t *testing.T) {
	t.Parallel()

	hintsStore := netstate.NewHints()
	hint := mustIPv6(t, hintsLinkLocal)
	hintSet := []net.IP{hint}

	hintsStore.Store("eth0", hintSet)
	assert.True(t, hintsStore.Has("eth0"))

	hintSet[0][0] = 0xaa
	first := hintsStore.Hints("eth0")
	assert.Len(t, first, 1)
	assert.NotEqual(t, byte(0xaa), first[0][0], "store should clone inputs")

	first[0][0] = 0xbb
	second := hintsStore.Hints("eth0")
	assert.NotEqual(t, byte(0xbb), second[0][0], "hints should clone outputs")
	assert.False(t, hintsStore.Has("eth1"))
}

func TestHintsDiscoverUsesResolverAndFilter(t *testing.T) {
	t.Parallel()

	filter := func(ip net.IP) bool { return ip.IsLinkLocalUnicast() && ip[15] != 0xcd }
	hintsStore := netstate.NewHints(
		netstate.WithHintsFilter(filter),
		netstate.WithInterfaceAddrsFunc(func(*net.Interface) ([]net.Addr, error) {
			return []net.Addr{
				mustCIDR(t, hintsLinkLocal+"/128"),
				mustCIDR(t, "2001:db8::1/64"),
				mustCIDR(t, "fe80::cd/128"),
				mustCIDR(t, "192.0.2.1/32"),
			}, nil
		}),
	)

	ipc := &net.Interface{Name: "eth0"}
	addrs, err := hintsStore.Discover(ipc)
	require.NoError(t, err)
	assert.Len(t, addrs, 1)
	assert.Equal(t, hintsLinkLocal, addrs[0].String())

	addrs[0][0] = 0xaa
	addrs2, err := hintsStore.Discover(ipc)
	require.NoError(t, err)
	assert.NotEqual(t, byte(0xaa), addrs2[0][0], "discover should clone results")
}

func TestHintsDiscoverNilInterface(t *testing.T) {
	t.Parallel()

	hintsStore := netstate.NewHints()
	_, err := hintsStore.Discover(nil)
	require.ErrorIs(t, err, netstate.ErrNilInterface)
}

func TestNewHintsInitialMapCloned(t *testing.T) {
	t.Parallel()

	initial := map[string][]net.IP{
		"eth0": {mustIPv6(t, hintsLinkLocal)},
	}
	hintsStore := netstate.NewHints(netstate.WithInitialHints(initial))

	initial["eth0"][0][0] = 0xaa
	initial["eth0"] = append(initial["eth0"], mustIPv6(t, "fe80::2"))

	got := hintsStore.Hints("eth0")
	assert.Len(t, got, 1)
	assert.NotEqual(t, byte(0xaa), got[0][0], "initial hints should be cloned")
}

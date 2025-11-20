package serviceutil_test

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/netstate"
	"github.com/jkoelker/ipv6relayd/pkg/serviceutil"
	"github.com/jkoelker/ipv6relayd/pkg/testutil"
)

type fakeLookup struct {
	ifaces map[string]*net.Interface
	errs   map[string]error
}

func (f *fakeLookup) ByName(name string) (*net.Interface, error) {
	if err, ok := f.errs[name]; ok {
		return nil, err
	}

	if ifc, ok := f.ifaces[name]; ok {
		return ifc, nil
	}

	return nil, fmt.Errorf("iface %s not found", name)
}

func TestHintManagerCaptureAndBootstrap(t *testing.T) {
	t.Parallel()
	addrMap := addrResolverMap(t, map[string][]string{
		"wan":  {"2001:db8:ffff::1/128"},
		"lan0": {"2001:db8:1::1/128"},
	})

	store := netstate.NewHints(netstate.WithInterfaceAddrsFunc(func(ifc *net.Interface) ([]net.Addr, error) {
		if addrs, ok := addrMap[ifc.Name]; ok {
			return addrs, nil
		}

		return nil, fmt.Errorf("no addrs for %s", ifc.Name)
	}))

	lookup := &fakeLookup{ifaces: map[string]*net.Interface{
		"wan":  {Name: "wan", Index: 1},
		"lan0": {Name: "lan0", Index: 2},
	}}

	mgr := serviceutil.NewHintManager(store, lookup, testutil.LoggerFromTB(t))

	upstream := config.InterfaceConfig{IfName: "wan", AddressHints: []string{"2001:db8::ff"}}
	downstreams := []config.InterfaceConfig{{IfName: "lan0"}}

	mgr.CaptureAll(upstream, downstreams)

	got := mgr.Hints("wan")
	require.Len(t, got, 1, "upstream hint overwritten")
	assert.True(t, got[0].Equal(net.ParseIP("2001:db8::ff")))

	mgr.Bootstrap(upstream, downstreams)

	got = mgr.Hints("lan0")
	require.Len(t, got, 1, "lan0 hints")
	assert.True(t, got[0].Equal(net.ParseIP("2001:db8:1::1")))

	got = mgr.Hints("wan")
	require.Len(t, got, 1, "explicit upstream hint replaced")
	assert.True(t, got[0].Equal(net.ParseIP("2001:db8::ff")))
}

func TestHintManagerEnsureHandlesFailures(t *testing.T) {
	t.Parallel()
	store := netstate.NewHints(netstate.WithInterfaceAddrsFunc(func(*net.Interface) ([]net.Addr, error) {
		return nil, errors.New("addr discovery failed")
	}))

	lookup := &fakeLookup{
		ifaces: map[string]*net.Interface{"wan": {Name: "wan"}},
		errs:   map[string]error{"wan": errors.New("lookup failed")},
	}

	mgr := serviceutil.NewHintManager(store, lookup, testutil.LoggerFromTB(t))

	mgr.Ensure("wan")
	assert.Empty(t, mgr.Hints("wan"), "unexpected hints after lookup failure")

	delete(lookup.errs, "wan")
	mgr.Ensure("wan")
	assert.Empty(t, mgr.Hints("wan"), "unexpected hints after discovery failure")
}

func TestHintManagerDiscoverInterface(t *testing.T) {
	t.Parallel()
	addrMap := addrResolverMap(t, map[string][]string{
		"lan0": {"2001:db8:1::1/128"},
	})

	store := netstate.NewHints(netstate.WithInterfaceAddrsFunc(func(ifc *net.Interface) ([]net.Addr, error) {
		if addrs, ok := addrMap[ifc.Name]; ok {
			return addrs, nil
		}

		return nil, fmt.Errorf("no addrs for %s", ifc.Name)
	}))

	mgr := serviceutil.NewHintManager(store, &fakeLookup{}, testutil.LoggerFromTB(t))

	hints := mgr.DiscoverInterface(&net.Interface{Name: "lan0"})
	require.Len(t, hints, 1)
	assert.True(t, hints[0].Equal(net.ParseIP("2001:db8:1::1")))

	assert.Nil(t, mgr.DiscoverInterface(nil))
}

func addrResolverMap(t *testing.T, inputs map[string][]string) map[string][]net.Addr {
	t.Helper()

	result := make(map[string][]net.Addr, len(inputs))
	for ifName, cidrs := range inputs {
		addrs := make([]net.Addr, 0, len(cidrs))
		for _, cidr := range cidrs {
			_, network, err := net.ParseCIDR(cidr)
			require.NoErrorf(t, err, "parse cidr %s", cidr)
			addrs = append(addrs, network)
		}
		result[ifName] = addrs
	}

	return result
}

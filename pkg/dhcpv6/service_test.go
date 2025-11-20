package dhcpv6_test

import (
	"fmt"
	"net"
	"testing"
	"time"

	insdhcpv6 "github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/insomniacslk/dhcp/rfc1035label"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/dhcpv6"
	"github.com/jkoelker/ipv6relayd/pkg/iface"
	"github.com/jkoelker/ipv6relayd/pkg/testutil"
)

func TestHardwareFromDUID(t *testing.T) {
	tests := []struct {
		name     string
		duid     insdhcpv6.DUID
		wantType iana.HWType
		wantHW   net.HardwareAddr
		ok       bool
	}{
		{
			name: "DUID-LL",
			duid: &insdhcpv6.DUIDLL{
				HWType: iana.HWTypeEthernet,
				LinkLayerAddr: net.HardwareAddr{
					0xde, 0xad, 0xbe, 0xef, 0x00, 0x01,
				},
			},
			wantType: iana.HWTypeEthernet,
			wantHW:   net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01},
			ok:       true,
		},
		{
			name: "DUID-LLT",
			duid: &insdhcpv6.DUIDLLT{
				HWType: iana.HWTypeEthernet,
				LinkLayerAddr: net.HardwareAddr{
					0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
				},
			},
			wantType: iana.HWTypeEthernet,
			wantHW:   net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			ok:       true,
		},
		{
			name: "Unsupported",
			duid: &insdhcpv6.DUIDEN{
				EnterpriseNumber:     1,
				EnterpriseIdentifier: []byte("test"),
			},
			wantType: 0,
			wantHW:   nil,
			ok:       false,
		},
	}

	t.Parallel()

	for _, tt := range tests {
		testCase := tt
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			gotType, gotHW, ok := dhcpv6.HardwareFromDUID(testCase.duid)
			assert.Equal(t, testCase.ok, ok, "HardwareFromDUID ok")
			if !ok {
				return
			}
			assert.Equal(t, testCase.wantType, gotType, "HardwareFromDUID hwType")
			assert.Equal(t, testCase.wantHW, gotHW, "HardwareFromDUID hw")
			assert.NotSame(t, &testCase.wantHW[0], &gotHW[0], "HardwareFromDUID returned alias to input slice")
		})
	}
}

func TestRemoteIDPayload(t *testing.T) {
	t.Parallel()

	ifaceWithMAC := &net.Interface{
		Name:         "lan0",
		HardwareAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}
	assert.Equal(t, "lan0/AA:BB:CC:DD:EE:FF", string(
		dhcpv6.GenerateRemoteIDPayload(config.RemoteIDConfig{}, ifaceWithMAC),
	))

	ifaceNoMAC := &net.Interface{Name: "lan1"}
	assert.Equal(t, "lan1", string(dhcpv6.GenerateRemoteIDPayload(config.RemoteIDConfig{}, ifaceNoMAC)))

	disabled := config.RemoteIDConfig{Disabled: true}
	assert.Empty(t, dhcpv6.GenerateRemoteIDPayload(disabled, ifaceWithMAC))

	custom := config.RemoteIDConfig{Template: "{ifname}-{mac}"}
	wantCustom := "lan0-AA:BB:CC:DD:EE:FF"
	assert.Equal(t, wantCustom, string(dhcpv6.GenerateRemoteIDPayload(custom, ifaceWithMAC)))
}

func TestRelayForwardSkipsRemoteIDWithoutEnterpriseID(t *testing.T) {
	t.Parallel()

	svc := newTestService(t)

	msg := &insdhcpv6.Message{MessageType: insdhcpv6.MessageTypeSolicit}
	relay, err := svc.BuildRelayForward(
		msg,
		net.ParseIP("2001:db8::1"),
		net.ParseIP("2001:db8::2"),
		&net.Interface{Name: "lan0"},
	)
	require.NoError(t, err)

	assert.Empty(t, relay.Options.Get(insdhcpv6.OptionRemoteID), "remote-id must be omitted without enterprise_id")
}

func TestSelectLinkAddressPrefersHints(t *testing.T) {
	t.Parallel()

	logger := testutil.LoggerFromTB(t)
	svc := newTestService(
		t,
		dhcpv6.WithLogger(logger),
		dhcpv6.WithUpstreamInterface(config.InterfaceConfig{IfName: "wan"}),
		dhcpv6.WithAddressHints(map[string][]net.IP{
			"lan0": {net.ParseIP("2001:db8:1::1")},
			"wan":  {net.ParseIP("2001:db8:ffff::1")},
		}),
	)
	got := svc.SelectLinkAddress(nil, config.InterfaceConfig{IfName: "lan0"}, nil)
	require.NotNil(t, got, "expected lan hint address")
	assert.True(t, got.Equal(net.ParseIP("2001:db8:1::1")))

	// No downstream hint; expect no downstream address (RFC 8415 -> use ::).
	got = svc.SelectLinkAddress(nil, config.InterfaceConfig{IfName: "lan1"}, nil)
	assert.Nil(t, got)
}

func TestSelectLinkAddressUsesConfiguredLinkLocal(t *testing.T) {
	t.Parallel()

	svc := newTestService(
		t,
		dhcpv6.WithUpstreamInterface(config.InterfaceConfig{IfName: "wan"}),
		dhcpv6.WithDownstreamInterfaces(config.InterfaceConfig{IfName: "lan0", LinkLocal: "fe80::1234"}),
	)

	got := svc.SelectLinkAddress(nil, config.InterfaceConfig{IfName: "lan0"}, nil)
	want := net.ParseIP("fe80::1234")
	require.NotNil(t, got)
	assert.True(t, got.Equal(want), "expected configured link-local")
}

func TestSelectLinkAddressPrefersLinkLocalOverGlobal(t *testing.T) {
	t.Parallel()

	linkLocal := net.ParseIP("fe80::1")
	global := net.ParseIP("2001:db8::1")

	svc := newTestService(
		t,
		dhcpv6.WithUpstreamInterface(config.InterfaceConfig{IfName: "wan"}),
		dhcpv6.WithAddressHints(map[string][]net.IP{
			"lan0": {global, linkLocal},
		}),
	)

	got := svc.SelectLinkAddress(nil, config.InterfaceConfig{IfName: "lan0"}, nil)
	require.NotNil(t, got)
	assert.True(t, got.Equal(global), "global/ULA should be preferred for relay link-address")
}

func TestStoreTransactionExpiry(t *testing.T) {
	t.Parallel()

	svc := newTestService(t, dhcpv6.WithTransactionTTL(10*time.Millisecond))

	svc.StoreTransaction(1, "lan0")
	ifaceName, expires, ok := svc.TransactionRecord(1)
	require.True(t, ok, "transaction not stored")
	assert.Equal(t, "lan0", ifaceName, "transaction interface")
	assert.True(t, expires.After(time.Now()), "transaction expiry not in future")

	assert.True(t, svc.TransactionExists(1), "transaction missing before ttl")
	time.Sleep(25 * time.Millisecond)
	assert.False(t, svc.TransactionExists(1), "transaction still present after ttl")
	_, _, ok = svc.TransactionRecord(1)
	assert.False(t, ok, "expired transaction still retrievable")
}

func TestAutoDiscoverUpstream(t *testing.T) {
	t.Parallel()

	mgr := iface.NewManager()
	mgr.Inject("wan", &net.Interface{Name: "wan", Index: 10})

	upstream := config.InterfaceConfig{IfName: "wan"}

	t.Run("prefers link-local gateway", func(t *testing.T) {
		t.Parallel()

		addr, err := dhcpv6.AutoDiscoverUpstreamWithRoutes(
			upstream,
			mgr,
			func(
				_ int,
				_ *netlink.Route,
				_ uint64,
			) ([]netlink.Route, error) {
				return []netlink.Route{
						{
							LinkIndex: 10,
							Gw:        net.ParseIP("fe80::1"),
						},
						{
							LinkIndex: 10,
							Gw:        net.ParseIP("2001:db8::1"),
						},
					},
					nil
			},
		)
		require.NoError(t, err)
		assert.Equal(t, "[fe80::1%wan]:547", addr.String())
	})

	t.Run("falls back to global gateway", func(t *testing.T) {
		t.Parallel()

		addr, err := dhcpv6.AutoDiscoverUpstreamWithRoutes(
			upstream,
			mgr,
			func(
				_ int,
				_ *netlink.Route,
				_ uint64,
			) ([]netlink.Route, error) {
				return []netlink.Route{
						{
							LinkIndex: 10,
							Gw:        net.ParseIP("2001:db8::1"),
						},
					},
					nil
			},
		)
		require.NoError(t, err)
		assert.Empty(t, addr.Zone, "expected empty zone")
		assert.Equal(t, "2001:db8::1", addr.IP.String())
	})

	t.Run("errors when no default route", func(t *testing.T) {
		t.Parallel()

		_, err := dhcpv6.AutoDiscoverUpstreamWithRoutes(
			upstream,
			mgr,
			func(_ int, _ *netlink.Route, _ uint64) ([]netlink.Route, error) {
				return nil, nil
			},
		)
		require.Error(t, err, "expected error for missing route")
	})
}

func TestRewriteReplyOptionsOverridesDNSAndSearch(t *testing.T) {
	t.Parallel()

	logger := testutil.LoggerFromTB(t)
	svc := newTestService(
		t,
		dhcpv6.WithConfig(config.DHCPv6Config{Upstream: "[2001:db8::1]:547", ForceReplyDNSRewrite: true}),
		dhcpv6.WithLogger(logger),
		dhcpv6.WithDNSOverride([]net.IP{net.ParseIP("2001:db8:53::53"), net.ParseIP("2001:db8:54::54")}),
		dhcpv6.WithDNSSearchLabels(&rfc1035label.Labels{Labels: []string{"lan.example"}}),
	)

	msg := &insdhcpv6.Message{
		MessageType: insdhcpv6.MessageTypeReply,
	}
	msg.Options.Add(insdhcpv6.OptDNS(net.ParseIP("2001:db8::1")))
	msg.Options.Add(insdhcpv6.OptDomainSearchList(&rfc1035label.Labels{
		Labels: []string{"old.example"},
	}))

	assert.True(t, svc.RewriteReplyOptions(msg))

	dns := msg.Options.DNS()
	require.Len(t, dns, 2)
	assert.True(t, dns[0].Equal(net.ParseIP("2001:db8:53::53")))
	assert.True(t, dns[1].Equal(net.ParseIP("2001:db8:54::54")))

	search := msg.Options.DomainSearchList()
	require.NotNil(t, search)
	require.Len(t, search.Labels, 1)
	assert.Equal(t, "lan.example", search.Labels[0])
}

func TestRewriteReplyOptionsSkipsWhenAuthenticated(t *testing.T) {
	t.Parallel()

	logger := testutil.LoggerFromTB(t)
	svc := newTestService(
		t,
		dhcpv6.WithConfig(config.DHCPv6Config{Upstream: "[2001:db8::1]:547", ForceReplyDNSRewrite: true}),
		dhcpv6.WithLogger(logger),
		dhcpv6.WithDNSOverride([]net.IP{net.ParseIP("2001:db8:53::53")}),
		dhcpv6.WithDNSSearchLabels(&rfc1035label.Labels{Labels: []string{"lan.example"}}),
	)

	msg := &insdhcpv6.Message{
		MessageType: insdhcpv6.MessageTypeReply,
	}
	msg.Options.Add(&insdhcpv6.OptionGeneric{
		OptionCode: insdhcpv6.OptionAuth,
		OptionData: []byte{0x01},
	})
	msg.Options.Add(insdhcpv6.OptDNS(net.ParseIP("2001:db8::1")))

	assert.False(t, svc.RewriteReplyOptions(msg), "authentication should skip rewrites")

	dns := msg.Options.DNS()
	require.Len(t, dns, 1)
	assert.True(t, dns[0].Equal(net.ParseIP("2001:db8::1")))

	assert.Nil(t, msg.Options.DomainSearchList())
}

func TestBootstrapAddressHintsDHCPv6(t *testing.T) {
	t.Parallel()

	addrMap := map[string][]net.Addr{
		"wan": {
			&net.IPNet{IP: net.ParseIP("2001:db8:ffff::1"), Mask: net.CIDRMask(64, 128)},
		},
		"lan0": {
			&net.IPNet{IP: net.ParseIP("2001:db8:1::1"), Mask: net.CIDRMask(64, 128)},
		},
	}
	ifaceAddrs := func(ifc *net.Interface) ([]net.Addr, error) {
		if addrs, ok := addrMap[ifc.Name]; ok {
			return addrs, nil
		}

		return nil, fmt.Errorf("no addrs for %s", ifc.Name)
	}

	mgr := iface.NewManager()
	mgr.Inject("wan", &net.Interface{Name: "wan", Index: 11})
	mgr.Inject("lan0", &net.Interface{Name: "lan0", Index: 12})

	logger := testutil.LoggerFromTB(t)
	svc := newTestService(
		t,
		dhcpv6.WithUpstreamInterface(config.InterfaceConfig{IfName: "wan"}),
		dhcpv6.WithDownstreamInterfaces(config.InterfaceConfig{IfName: "lan0"}),
		dhcpv6.WithInterfaceManager(mgr),
		dhcpv6.WithLogger(logger),
		dhcpv6.WithInterfaceAddrs(ifaceAddrs),
	)

	svc.BootstrapAddressHints()
	got := svc.AddressHints("wan")
	require.Len(t, got, 1, "wan hints")
	assert.True(t, got[0].Equal(net.ParseIP("2001:db8:ffff::1")))
	got = svc.AddressHints("lan0")
	require.Len(t, got, 1, "lan0 hints")
	assert.True(t, got[0].Equal(net.ParseIP("2001:db8:1::1")))

	t.Run("preserves explicit hints", func(t *testing.T) {
		t.Parallel()

		svc := newTestService(
			t,
			dhcpv6.WithUpstreamInterface(config.InterfaceConfig{IfName: "wan"}),
			dhcpv6.WithDownstreamInterfaces(config.InterfaceConfig{IfName: "lan0"}),
			dhcpv6.WithInterfaceManager(mgr),
			dhcpv6.WithLogger(logger),
			dhcpv6.WithInterfaceAddrs(ifaceAddrs),
			dhcpv6.WithAddressHints(map[string][]net.IP{
				"lan0": {net.ParseIP("2001:db8:1::99")},
			}),
		)
		svc.BootstrapAddressHints()
		got := svc.AddressHints("lan0")
		require.Len(t, got, 1, "explicit hint overwritten")
		assert.True(t, got[0].Equal(net.ParseIP("2001:db8:1::99")))
	})
}

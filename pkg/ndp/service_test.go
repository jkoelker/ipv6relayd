package ndp_test

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/iface"
	ndp "github.com/jkoelker/ipv6relayd/pkg/ndp"
	"github.com/jkoelker/ipv6relayd/pkg/testutil"
)

const (
	redirectHeaderLen  = 40
	linkLayerOptionLen = 8
)

func newTestNDPService(t *testing.T, opts ...func(*ndp.Options)) *ndp.Service {
	t.Helper()

	events, cancel := newTestInterfaceEvents()
	mgr := iface.NewManager()
	mgr.Inject("wan", &net.Interface{Name: "wan", Index: 1})
	mgr.Inject("lan0", &net.Interface{Name: "lan0", Index: 2})

	baseOpts := []func(*ndp.Options){
		ndp.WithLogger(testutil.LoggerFromTB(t)),
		ndp.WithInterfaceEvents(events, cancel),
	}
	baseOpts = append(baseOpts, opts...)

	svc, err := ndp.New(
		config.InterfaceConfig{IfName: "wan"},
		[]config.InterfaceConfig{{IfName: "lan0"}},
		config.NDPConfig{Mode: "relay"},
		mgr,
		baseOpts...,
	)
	require.NoError(t, err)

	return svc
}

func TestPrepareRedirectUsesTargetHardware(t *testing.T) {
	t.Parallel()

	svc := newTestNDPService(t)
	iface := &net.Interface{
		Name:         "lan0",
		HardwareAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}
	payload := buildRedirectPayload(true)
	targetHW := net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}

	out, err := svc.PrepareRedirect(payload, iface, targetHW)
	require.NoError(t, err)

	targetOpt := findRedirectOption(out, 2)
	require.NotNil(t, targetOpt, "expected target option")

	if got := targetOpt[2 : 2+len(targetHW)]; !bytes.Equal(got, targetHW) {
		assert.Equal(t, targetHW, got, "target option")
	}

	sourceOpt := findRedirectOption(out, 1)
	require.NotNil(t, sourceOpt, "expected source option")

	if got := sourceOpt[2 : 2+len(iface.HardwareAddr)]; !bytes.Equal(got, iface.HardwareAddr) {
		assert.Equal(t, iface.HardwareAddr, got, "source option")
	}
}

func TestPrepareRedirectAppendsTargetOptionWhenMissing(t *testing.T) {
	t.Parallel()

	svc := newTestNDPService(t)
	iface := &net.Interface{
		Name:         "lan0",
		HardwareAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}
	targetHW := net.HardwareAddr{0x10, 0x11, 0x12, 0x13, 0x14, 0x15}
	payload := buildRedirectPayload(false)

	out, err := svc.PrepareRedirect(payload, iface, targetHW)
	require.NoError(t, err)

	targetOpt := findRedirectOption(out, 2)
	require.NotNil(t, targetOpt, "expected target option")

	if got := targetOpt[2 : 2+len(targetHW)]; !bytes.Equal(got, targetHW) {
		assert.Equal(t, targetHW, got, "target option")
	}
}

func TestPrepareRedirectDropsTargetOptionWhenHardwareMissing(t *testing.T) {
	t.Parallel()

	svc := newTestNDPService(t)
	iface := &net.Interface{
		Name:         "lan0",
		HardwareAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}
	payload := buildRedirectPayload(true)

	out, err := svc.PrepareRedirect(payload, iface, nil)
	require.NoError(t, err)

	assert.Nil(t, findRedirectOption(out, 2), "unexpected target option when hardware is missing")
}

func buildRedirectPayload(includeTarget bool) []byte {
	payload := make([]byte, 0, redirectHeaderLen+2*linkLayerOptionLen)
	payload = append(payload, make([]byte, redirectHeaderLen)...)
	payload = append(payload, encodeLinkLayerOption(1, net.HardwareAddr{0, 0, 0, 0, 0, 0})...)

	if includeTarget {
		payload = append(payload, encodeLinkLayerOption(2, net.HardwareAddr{0, 0, 0, 0, 0, 0})...)
	}

	return payload
}

func findRedirectOption(payload []byte, optType byte) []byte {
	offset := redirectHeaderLen

	for offset+1 < len(payload) {
		optLenUnits := int(payload[offset+1])
		if optLenUnits == 0 {
			return nil
		}

		optLen := optLenUnits * 8
		if offset+optLen > len(payload) {
			return nil
		}

		if payload[offset] == optType {
			return payload[offset : offset+optLen]
		}

		offset += optLen
	}

	return nil
}

func encodeLinkLayerOption(optType byte, hw net.HardwareAddr) []byte {
	option := make([]byte, linkLayerOptionLen)
	option[0] = optType
	option[1] = byte(linkLayerOptionLen / 8)
	copy(option[2:], hw)

	return option
}

func TestBootstrapAddressHintsNDP(t *testing.T) {
	t.Parallel()

	addrMap := map[string][]net.Addr{
		"wan": {
			&net.IPNet{IP: net.ParseIP("2001:db8:ffff::2"), Mask: net.CIDRMask(64, 128)},
		},
		"lan0": {
			&net.IPNet{IP: net.ParseIP("2001:db8:1::2"), Mask: net.CIDRMask(64, 128)},
		},
	}

	ifaceAddrs := func(ifc *net.Interface) ([]net.Addr, error) {
		if addrs, ok := addrMap[ifc.Name]; ok {
			return addrs, nil
		}

		return nil, fmt.Errorf("no addrs for %s", ifc.Name)
	}

	mgr := iface.NewManager()
	mgr.Inject("wan", &net.Interface{Name: "wan", Index: 21})
	mgr.Inject("lan0", &net.Interface{Name: "lan0", Index: 22})

	logger := testutil.LoggerFromTB(t)

	svc := newTestNDPService(
		t,
		ndp.WithInterfaceManager(mgr),
		ndp.WithInterfaceAddrs(ifaceAddrs),
		ndp.WithLogger(logger),
	)

	svc.BootstrapAddressHints()

	got := svc.AddressHints("wan")
	require.Len(t, got, 1, "wan hints")
	assert.True(t, got[0].Equal(net.ParseIP("2001:db8:ffff::2")))

	got = svc.AddressHints("lan0")
	require.Len(t, got, 1, "lan0 hints")
	assert.True(t, got[0].Equal(net.ParseIP("2001:db8:1::2")))

	t.Run("preserves explicit hints", func(t *testing.T) {
		t.Parallel()

		svc := newTestNDPService(
			t,
			ndp.WithInterfaceManager(mgr),
			ndp.WithInterfaceAddrs(ifaceAddrs),
			ndp.WithLogger(logger),
			ndp.WithAddressHints(map[string][]net.IP{
				"lan0": {net.ParseIP("2001:db8:1::99")},
			}),
		)
		svc.BootstrapAddressHints()

		got := svc.AddressHints("lan0")
		require.Len(t, got, 1, "explicit hint overwritten")
		assert.True(t, got[0].Equal(net.ParseIP("2001:db8:1::99")))
	})
}

func TestForEachDownstreamContinuesAfterError(t *testing.T) {
	t.Parallel()

	svc := newTestNDPService(t)

	downstreams := []*net.Interface{
		{Name: "lan0"},
		{Name: "lan1"},
	}

	sentinel := errors.New("boom")

	var calls int

	err := svc.ForEachDownstream(downstreams, func(_ *net.Interface) error {
		calls++

		if calls == 1 {
			return sentinel
		}

		return nil
	})

	require.ErrorIs(t, err, sentinel)
	assert.Equal(t, len(downstreams), calls, "callback count")
}

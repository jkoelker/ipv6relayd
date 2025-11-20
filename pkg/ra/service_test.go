package ra_test

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/ndp"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/ipv6"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/ra"
)

const (
	testRAHeaderLength = 16
	testRSHeaderLength = 8
)

func TestRALifetimeIncludesPIO(t *testing.T) {
	t.Parallel()

	payload := buildRAPayload(600*time.Second, prefixInfoOption(180*time.Second, 90*time.Second))

	assert.Equal(t, 180*time.Second, ra.Lifetime(payload))
}

func TestRALifetimeIncludesRouteInfo(t *testing.T) {
	t.Parallel()

	payload := buildRAPayload(1200*time.Second, routeInfoOption(300*time.Second))

	assert.Equal(t, 300*time.Second, ra.Lifetime(payload))
}

func TestRALifetimeIgnoresZeroLifetimeOption(t *testing.T) {
	t.Parallel()

	payload := buildRAPayload(900*time.Second, prefixInfoOption(0, 10*time.Second))

	assert.Equal(t, 900*time.Second, ra.Lifetime(payload))
}

func TestRALifetimeFallsBackToRouterLifetime(t *testing.T) {
	t.Parallel()

	payload := buildRAPayload(700 * time.Second)

	assert.Equal(t, 700*time.Second, ra.Lifetime(payload))
}

func TestRALifetimeUsesOptionWhenRouterLifetimeZero(t *testing.T) {
	t.Parallel()

	payload := buildRAPayload(0,
		prefixInfoOption(600*time.Second, 400*time.Second),
		routeInfoOption(120*time.Second),
	)

	assert.Equal(t, 120*time.Second, ra.Lifetime(payload))
}

func buildRAPayload(routerLifetime time.Duration, options ...ndp.Option) []byte {
	msg := &ndp.RouterAdvertisement{
		RouterLifetime: routerLifetime,
		Options:        options,
	}

	raw, _ := ndp.MarshalMessage(msg)

	return raw
}

func prefixInfoOption(valid, preferred time.Duration) ndp.Option {
	return &ndp.PrefixInformation{
		PrefixLength:                   64,
		OnLink:                         true,
		AutonomousAddressConfiguration: true,
		ValidLifetime:                  valid,
		PreferredLifetime:              preferred,
		Prefix:                         netip.MustParseAddr("2001:db8::"),
	}
}

func routeInfoOption(lifetime time.Duration) ndp.Option {
	return &ndp.RouteInformation{
		PrefixLength:  0,
		RouteLifetime: lifetime,
	}
}

func TestHandleRouterSolicitationForwardsWhenValid(t *testing.T) {
	t.Parallel()

	upstreamIF := &net.Interface{
		Name:         "upstream0",
		Index:        10,
		HardwareAddr: []byte{0, 1, 2, 3, 4, 5},
	}
	downstreamIF := &net.Interface{
		Name:         "downstream0",
		Index:        20,
		HardwareAddr: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}

	var forwarded bool
	service := newTestRAService(
		t,
		upstreamIF,
		[]*net.Interface{downstreamIF},
		config.RAConfig{Mode: "relay"},
		ra.WithForwardToUpstream(func(context.Context, *ipv6.PacketConn, *net.Interface, []byte) error {
			forwarded = true

			return nil
		}),
	)

	rsPayload := make([]byte, testRSHeaderLength)
	ctrlMsg := &ipv6.ControlMessage{
		IfIndex:  downstreamIF.Index,
		HopLimit: 255,
	}
	src := &net.IPAddr{IP: net.ParseIP("fe80::1")}

	ctx := context.Background()
	_ = service.HandleRouterSolicitation(ctx, nil, upstreamIF, rsPayload, ctrlMsg, src)

	assert.True(t, forwarded, "forwardToUpstream not called for valid RS")
}

func TestHandleRouterSolicitationDropsInvalidHopLimit(t *testing.T) {
	t.Parallel()

	upstreamIF := &net.Interface{
		Name:         "upstream0",
		Index:        30,
		HardwareAddr: []byte{0, 1, 2, 3, 4, 6},
	}
	downstreamIF := &net.Interface{
		Name:         "downstream0",
		Index:        40,
		HardwareAddr: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x11},
	}

	var forwarded bool
	service := newTestRAService(
		t,
		upstreamIF,
		[]*net.Interface{downstreamIF},
		config.RAConfig{Mode: "relay"},
		ra.WithForwardToUpstream(func(context.Context, *ipv6.PacketConn, *net.Interface, []byte) error {
			forwarded = true

			return nil
		}),
	)

	rsPayload := make([]byte, testRSHeaderLength)
	ctrlMsg := &ipv6.ControlMessage{IfIndex: downstreamIF.Index, HopLimit: 254}
	src := &net.IPAddr{IP: net.ParseIP("fe80::1")}

	ctx := context.Background()
	_ = service.HandleRouterSolicitation(ctx, nil, upstreamIF, rsPayload, ctrlMsg, src)

	assert.False(t, forwarded, "forwardToUpstream called for RS with invalid hop-limit")
}

func TestHandleRouterSolicitationAllowsUnspecifiedSource(t *testing.T) {
	t.Parallel()

	upstreamIF := &net.Interface{
		Name:         "upstream0",
		Index:        30,
		HardwareAddr: []byte{0, 1, 2, 3, 4, 6},
	}
	downstreamIF := &net.Interface{
		Name:         "downstream0",
		Index:        40,
		HardwareAddr: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x11},
	}

	var forwarded bool
	service := newTestRAService(
		t,
		upstreamIF,
		[]*net.Interface{downstreamIF},
		config.RAConfig{Mode: "relay"},
		ra.WithForwardToUpstream(func(context.Context, *ipv6.PacketConn, *net.Interface, []byte) error {
			forwarded = true

			return nil
		}),
	)

	rsPayload := make([]byte, testRSHeaderLength)
	ctrlMsg := &ipv6.ControlMessage{IfIndex: downstreamIF.Index, HopLimit: 255}
	src := &net.IPAddr{IP: net.IPv6unspecified}

	ctx := context.Background()
	_ = service.HandleRouterSolicitation(ctx, nil, upstreamIF, rsPayload, ctrlMsg, src)

	assert.True(t, forwarded, "unspecified-source RS should be forwarded")
}

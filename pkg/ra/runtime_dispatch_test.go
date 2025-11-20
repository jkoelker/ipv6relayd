package ra_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/mdlayher/ndp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv6"

	"github.com/jkoelker/ipv6relayd/pkg/config"
)

func TestDispatchMessageDropsRouterAdvertisementWithInvalidHopLimit(t *testing.T) {
	t.Parallel()

	upstreamIF := &net.Interface{Name: "upstream0", Index: 10}
	downstreamIF := &net.Interface{Name: "downstream0", Index: 11}

	svc := newTestRAService(
		t,
		upstreamIF,
		[]*net.Interface{downstreamIF},
		config.RAConfig{Mode: "relay"},
	)

	ctx := context.Background()
	payload := buildTestRAPayload(300 * time.Second)
	ctrlMsg := &ipv6.ControlMessage{
		IfIndex:  upstreamIF.Index,
		HopLimit: 254,
	}
	src := &net.IPAddr{IP: net.ParseIP("fe80::1")}

	err := svc.DispatchMessage(ctx, nil, upstreamIF, payload, ctrlMsg, src)
	require.NoError(t, err)

	svcLast, _, _ := svc.LastRACache()
	assert.Empty(t, svcLast, "RA with invalid hop-limit should be dropped before caching/forwarding")
}

func buildTestRAPayload(routerLifetime time.Duration, options ...ndp.Option) []byte {
	msg := &ndp.RouterAdvertisement{
		RouterLifetime: routerLifetime,
		Options:        options,
	}

	raw, _ := ndp.MarshalMessage(msg)

	return raw
}

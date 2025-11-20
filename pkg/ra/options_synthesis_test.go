package ra_test

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/ndp"
	"github.com/stretchr/testify/require"

	"github.com/jkoelker/ipv6relayd/pkg/config"
)

const ndValidLimitSeconds = 5400

func TestRouterAdvertisementSynthesizesRDNSSWhenMissing(t *testing.T) {
	t.Parallel()

	msg := &ndp.RouterAdvertisement{
		RouterLifetime: 30 * time.Second,
	}

	svc := newTestRAService(t,
		&net.Interface{Name: "wan", Index: 1},
		[]*net.Interface{{Name: "lan0", Index: 2}},
		config.RAConfig{Mode: "relay", DNSRewrite: []string{"2001:db8::53"}},
	)

	raw, err := ndp.MarshalMessage(msg)
	require.NoError(t, err)

	out, err := svc.RewriteRouterAdvertisement(raw, &net.Interface{Name: "lan0"})
	require.NoError(t, err)

	parsed, err := ndp.ParseMessage(out)
	require.NoError(t, err)
	raMsg, ok := parsed.(*ndp.RouterAdvertisement)
	require.True(t, ok)

	found := false
	for _, opt := range raMsg.Options {
		rdnss, ok := opt.(*ndp.RecursiveDNSServer)
		if !ok {
			continue
		}

		found = true
		require.Equal(t, 30*time.Second, rdnss.Lifetime)
		require.Equal(t, []netip.Addr{netip.MustParseAddr("2001:db8::53")}, rdnss.Servers)
	}

	require.True(t, found, "expected synthesized RDNSS option")
}

func TestRouterAdvertisementSynthesizesDNSSLWhenMissing(t *testing.T) {
	t.Parallel()

	msg := &ndp.RouterAdvertisement{
		RouterLifetime: 45 * time.Second,
	}

	svc := newTestRAService(t,
		&net.Interface{Name: "wan", Index: 1},
		[]*net.Interface{{Name: "lan0", Index: 2}},
		config.RAConfig{Mode: "relay", DNSSearchRewrite: []string{"example.com"}},
	)

	raw, err := ndp.MarshalMessage(msg)
	require.NoError(t, err)

	out, err := svc.RewriteRouterAdvertisement(raw, &net.Interface{Name: "lan0"})
	require.NoError(t, err)

	parsed, err := ndp.ParseMessage(out)
	require.NoError(t, err)
	raMsg, ok := parsed.(*ndp.RouterAdvertisement)
	require.True(t, ok)

	found := false
	for _, opt := range raMsg.Options {
		dnssl, ok := opt.(*ndp.DNSSearchList)
		if !ok {
			continue
		}

		found = true
		require.Equal(t, 45*time.Second, dnssl.Lifetime)
		require.Contains(t, dnssl.DomainNames, "example.com")
	}

	require.True(t, found, "expected synthesized DNSSL option")
}

func TestRouterAdvertisementSynthesizedDNSLifetimeIsClamped(t *testing.T) {
	t.Parallel()

	msg := &ndp.RouterAdvertisement{
		// Intentionally large router lifetime (9000s) that exceeds RFC cap.
		RouterLifetime: 9000 * time.Second,
	}

	svc := newTestRAService(t,
		&net.Interface{Name: "wan", Index: 1},
		[]*net.Interface{{Name: "lan0", Index: 2}},
		config.RAConfig{Mode: "relay", DNSRewrite: []string{"2001:db8::53"}, DNSSearchRewrite: []string{"example.com"}},
	)

	raw, err := ndp.MarshalMessage(msg)
	require.NoError(t, err)

	out, err := svc.RewriteRouterAdvertisement(raw, &net.Interface{Name: "lan0"})
	require.NoError(t, err)

	parsed, err := ndp.ParseMessage(out)
	require.NoError(t, err)
	raMsg, ok := parsed.(*ndp.RouterAdvertisement)
	require.True(t, ok)

	for _, opt := range raMsg.Options {
		switch o := opt.(type) {
		case *ndp.RecursiveDNSServer:
			require.LessOrEqual(t, int(o.Lifetime/time.Second), ndValidLimitSeconds)
		case *ndp.DNSSearchList:
			require.LessOrEqual(t, int(o.Lifetime/time.Second), ndValidLimitSeconds)
		}
	}
}

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

const dnsValidLimit = 5400

func TestRewriteExistingDNSOptionsClampLifetime(t *testing.T) {
	t.Parallel()

	svc := newTestRAService(t,
		&net.Interface{Name: "wan", Index: 1},
		[]*net.Interface{{Name: "lan0", Index: 2}},
		config.RAConfig{Mode: "relay", DNSRewrite: []string{"2001:db8::53"}, DNSSearchRewrite: []string{"example.com"}},
	)

	iface := &net.Interface{
		Name:         "lan0",
		HardwareAddr: []byte{0, 1, 2, 3, 4, 5},
	}

	msg := &ndp.RouterAdvertisement{
		RouterLifetime: 1800 * time.Second,
		Options: []ndp.Option{
			&ndp.RecursiveDNSServer{
				Lifetime: 7 * time.Hour,
				Servers:  []netip.Addr{netip.MustParseAddr("fe80::1")},
			},
			&ndp.DNSSearchList{
				Lifetime:    7 * time.Hour,
				DomainNames: []string{"old.example"},
			},
		},
	}

	raw, err := ndp.MarshalMessage(msg)
	require.NoError(t, err)

	out, err := svc.RewriteRouterAdvertisement(raw, iface)
	require.NoError(t, err)

	parsed, err := ndp.ParseMessage(out)
	require.NoError(t, err)

	raMsg, ok := parsed.(*ndp.RouterAdvertisement)
	require.True(t, ok)

	for _, opt := range raMsg.Options {
		switch o := opt.(type) {
		case *ndp.RecursiveDNSServer:
			require.LessOrEqual(t, int(o.Lifetime/time.Second), dnsValidLimit, "lifetime should be clamped")
		case *ndp.DNSSearchList:
			require.LessOrEqual(t, int(o.Lifetime/time.Second), dnsValidLimit, "lifetime should be clamped")
		}
	}
}

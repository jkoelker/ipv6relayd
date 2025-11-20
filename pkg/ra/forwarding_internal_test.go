package ra

import (
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/ndp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jkoelker/ipv6relayd/pkg/testutil"
)

func TestStoreLastRAUsesMaxLifetime(t *testing.T) {
	t.Parallel()

	svc := &Service{log: testutil.LoggerFromTB(t)}

	msg := buildTestRAMessage(
		200*time.Second,
		&ndp.PrefixInformation{
			PrefixLength:                   64,
			OnLink:                         true,
			AutonomousAddressConfiguration: true,
			ValidLifetime:                  400 * time.Second,
			PreferredLifetime:              100 * time.Second,
			Prefix:                         netip.MustParseAddr("2001:db8::"),
		},
		&ndp.RecursiveDNSServer{
			Lifetime: 900 * time.Second,
			Servers:  []netip.Addr{netip.MustParseAddr("2001:db8::1")},
		},
	)

	svc.storeLastRA(msg)

	svc.lastRAMu.Lock()
	defer svc.lastRAMu.Unlock()

	require.NotEmpty(t, svc.lastRA, "expected cached RA payload")

	diff := svc.lastRAExpiry.Sub(svc.lastRAReceived)
	assert.Equal(t, 900*time.Second, diff)
}

func TestStoreLastRARemovesZeroLifetimeOptions(t *testing.T) {
	t.Parallel()

	svc := &Service{log: testutil.LoggerFromTB(t)}

	msg := buildTestRAMessage(
		900*time.Second,
		&ndp.PrefixInformation{
			PrefixLength:                   64,
			OnLink:                         true,
			AutonomousAddressConfiguration: true,
			ValidLifetime:                  0,
			PreferredLifetime:              100 * time.Second,
			Prefix:                         netip.MustParseAddr("2001:db8::"),
		},
		&ndp.RecursiveDNSServer{
			Lifetime: 300 * time.Second,
			Servers:  []netip.Addr{netip.MustParseAddr("2001:db8::1")},
		},
	)

	svc.storeLastRA(msg)

	svc.lastRAMu.Lock()
	defer svc.lastRAMu.Unlock()

	require.NotEmpty(t, svc.lastRA, "expected cached RA payload")

	parsed, err := ndp.ParseMessage(svc.lastRA)
	require.NoError(t, err)
	cached, ok := parsed.(*ndp.RouterAdvertisement)
	require.True(t, ok)

	hasPrefix := false
	hasRDNSS := false
	for _, opt := range cached.Options {
		switch optVal := opt.(type) {
		case *ndp.PrefixInformation:
			hasPrefix = true
			if optVal.ValidLifetime != 0 {
				hasPrefix = true
			}
		case *ndp.RecursiveDNSServer:
			hasRDNSS = true
			assert.Equal(t, 300*time.Second, optVal.Lifetime)
		}
	}

	if hasPrefix {
		assert.Fail(t, "zero-lifetime option was not pruned from cache")
	}

	require.True(t, hasRDNSS, "expected RDNSS option to remain in cache")

	diff := svc.lastRAExpiry.Sub(svc.lastRAReceived)
	assert.Equal(t, 900*time.Second, diff)
}

func TestClampRALifetimes(t *testing.T) {
	t.Parallel()

	msg := buildTestRAMessage(
		600*time.Second,
		&ndp.PrefixInformation{
			PrefixLength:                   64,
			OnLink:                         true,
			AutonomousAddressConfiguration: true,
			ValidLifetime:                  1200 * time.Second,
			PreferredLifetime:              400 * time.Second,
			Prefix:                         netip.MustParseAddr("2001:db8::"),
		},
		&ndp.RecursiveDNSServer{
			Lifetime: 900 * time.Second,
			Servers:  []netip.Addr{netip.MustParseAddr("2001:db8::1")},
		},
		&ndp.PREF64{
			Lifetime: 512 * time.Second,
			Prefix:   netip.MustParsePrefix("64:ff9b::/96"),
		},
	)

	payload, err := ndp.MarshalMessage(msg)
	require.NoError(t, err)

	clamped := append([]byte(nil), payload...)
	elapsed := 300 * time.Second

	hasRemaining, err := clampRALifetimes(clamped, elapsed)
	require.NoError(t, err)
	assert.True(t, hasRemaining, "clampRALifetimes reported no remaining lifetime")

	parsed, err := ndp.ParseMessage(clamped)
	require.NoError(t, err)
	clampedMsg, ok := parsed.(*ndp.RouterAdvertisement)
	require.True(t, ok)

	expectedRouter := max(600*time.Second-elapsed, 0)
	assert.Equal(t, expectedRouter, clampedMsg.RouterLifetime)

	var (
		foundPrefix bool
		foundRDNSS  bool
		foundPref64 bool
	)

	for _, opt := range clampedMsg.Options {
		switch optVal := opt.(type) {
		case *ndp.PrefixInformation:
			foundPrefix = true
			assert.Equal(t, 1200*time.Second-elapsed, optVal.ValidLifetime)
			assert.Equal(t, 400*time.Second-elapsed, optVal.PreferredLifetime)
		case *ndp.RecursiveDNSServer:
			foundRDNSS = true
			assert.Equal(t, 900*time.Second-elapsed, optVal.Lifetime)
		case *ndp.PREF64:
			foundPref64 = true
			expectedPref64Seconds := ((512 - int64(elapsed/time.Second)) / pref64LifetimeUnits) * pref64LifetimeUnits
			assert.Equal(t, time.Duration(expectedPref64Seconds)*time.Second, optVal.Lifetime)
		}
	}

	assert.True(t, foundPrefix)
	assert.True(t, foundRDNSS)
	assert.True(t, foundPref64)
}

func TestLoadLastRADropsExpired(t *testing.T) {
	t.Parallel()

	svc := &Service{log: testutil.LoggerFromTB(t)}

	msg := buildTestRAMessage(
		100*time.Second,
		&ndp.PrefixInformation{
			PrefixLength:                   64,
			OnLink:                         true,
			AutonomousAddressConfiguration: true,
			ValidLifetime:                  200 * time.Second,
			PreferredLifetime:              100 * time.Second,
			Prefix:                         netip.MustParseAddr("2001:db8::"),
		},
	)

	svc.storeLastRA(msg)

	elapsed := 300 * time.Second
	maxLifetime := maxRALifetime(msg)

	svc.lastRAMu.Lock()
	svc.lastRAReceived = svc.lastRAReceived.Add(-elapsed)
	svc.lastRAExpiry = svc.lastRAReceived.Add(maxLifetime)
	svc.lastRAMu.Unlock()

	assert.Nil(t, svc.loadLastRA(), "expected cache to expire")

	svc.lastRAMu.Lock()
	defer svc.lastRAMu.Unlock()

	assert.Empty(t, svc.lastRA, "expected cached RA to be cleared")
}

func buildTestRAMessage(routerLifetime time.Duration, options ...ndp.Option) *ndp.RouterAdvertisement {
	return &ndp.RouterAdvertisement{
		RouterLifetime: routerLifetime,
		Options:        options,
	}
}

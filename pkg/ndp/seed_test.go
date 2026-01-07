//nolint:testpackage // accessing unexported variables
package ndp

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

//nolint:paralleltest // modifying global variable
func TestSeedTargets(t *testing.T) {
	// t.Parallel() CANNOT run parallel because we are modifying a global variable `neighList`

	// Mock netlink.NeighList
	oldNeighList := neighList
	defer func() { neighList = oldNeighList }()

	validIP := net.ParseIP("2001:db8::1")
	staleIP := net.ParseIP("2001:db8::2")
	linkLocalIP := net.ParseIP("fe80::1")
	invalidIP := net.ParseIP("::")
	incompleteIP := net.ParseIP("2001:db8::3")

	mockNeighs := []netlink.Neigh{
		{
			IP:    validIP,
			State: netlink.NUD_REACHABLE,
		},
		{
			IP:    staleIP,
			State: netlink.NUD_STALE,
		},
		{
			IP:    linkLocalIP,
			State: netlink.NUD_REACHABLE, // Should be ignored (LL)
		},
		{
			IP:    invalidIP,
			State: netlink.NUD_REACHABLE, // Should be ignored (unspecified)
		},
		{
			IP:    incompleteIP,
			State: netlink.NUD_INCOMPLETE, // Should be ignored (invalid state)
		},
	}

	neighList = func(linkIndex, _ int) ([]netlink.Neigh, error) {
		if linkIndex == 2 { // downstream index
			return mockNeighs, nil
		}
		if linkIndex == 3 { // error index
			return nil, errors.New("mock error")
		}

		return nil, nil
	}

	upstream := &net.Interface{Index: 1, Name: "eth0", HardwareAddr: net.HardwareAddr{0, 0, 0, 0, 0, 1}}
	downstream := &net.Interface{Index: 2, Name: "eth1", HardwareAddr: net.HardwareAddr{0, 0, 0, 0, 0, 2}}

	t.Run("SeedTargetsSuccess", func(t *testing.T) {
		// t.Parallel() CANNOT run parallel
		targetCache := newTargetCache(time.Minute, nil)
		svc := &Service{
			targetCache: targetCache,
		}

		svc.seedTargets(upstream, []*net.Interface{downstream})

		// Check if valid IPs were added
		// We use ipToKey because targetCache keys are strings
		keyValid, _ := ipToKey(validIP)
		_, existsValid, _ := targetCache.cache.Get(keyValid)
		assert.True(t, existsValid, "Valid IP should be in cache")

		keyStale, _ := ipToKey(staleIP)
		_, existsStale, _ := targetCache.cache.Get(keyStale)
		assert.True(t, existsStale, "Stale IP should be in cache")

		// Check if invalid IPs were ignored
		keyLL, _ := ipToKey(linkLocalIP)
		_, existsLL, _ := targetCache.cache.Get(keyLL)
		assert.False(t, existsLL, "Link-local IP should not be in cache")

		keyInvalid, _ := ipToKey(invalidIP)
		_, existsInvalid, _ := targetCache.cache.Get(keyInvalid)
		assert.False(t, existsInvalid, "Invalid/unspecified IP should not be in cache")

		keyIncomplete, _ := ipToKey(incompleteIP)
		_, existsIncomplete, _ := targetCache.cache.Get(keyIncomplete)
		assert.False(t, existsIncomplete, "Incomplete state IP should not be in cache")
	})
}

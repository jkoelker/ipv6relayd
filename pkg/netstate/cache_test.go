package netstate_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jkoelker/ipv6relayd/pkg/netstate"
)

func TestLinkLocalCacheStoreLookup(t *testing.T) {
	t.Parallel()

	cache := netstate.NewLinkLocalCache()
	addr := net.ParseIP("fe80::1")
	cache.Store("eth0", 1, addr)

	out := cache.Lookup("eth0")
	assert.NotNil(t, out, "expected to find stored address")
	assert.Equal(t, addr, out, "expected stored address to match retrieved address")

	out[15]++

	assert.NotEqual(
		t,
		cache.Lookup("eth0"),
		out,
		"expected cache to return a copy, not a shared reference",
	)
}

func TestLinkLocalCacheInvalidateName(t *testing.T) {
	t.Parallel()

	cache := netstate.NewLinkLocalCache()
	cache.Store("eth0", 1, net.ParseIP("fe80::1"))
	cache.InvalidateName("eth0")

	assert.Nil(t, cache.Lookup("eth0"), "expected entry to be invalidated")
}

func TestLinkLocalCacheInvalidateIndex(t *testing.T) {
	t.Parallel()

	cache := netstate.NewLinkLocalCache()
	cache.Store("eth0", 42, net.ParseIP("fe80::2"))
	cache.InvalidateIndex(42)

	assert.Nil(t, cache.Lookup("eth0"), "expected entry to be invalidated by index")
}

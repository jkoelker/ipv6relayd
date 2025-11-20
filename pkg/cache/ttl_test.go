package cache_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jkoelker/ipv6relayd/pkg/cache"
)

func TestTTLBasicOperations(t *testing.T) {
	t.Parallel()

	ttl := cache.NewTTL[string, int](time.Minute)
	require.NotNil(t, ttl, "expected cache instance")

	ttl.Add("alpha", 42)

	val, ok, expired := ttl.Get("alpha")
	assert.True(t, ok, "expected cache hit")
	assert.False(t, expired, "expected non-expired entry")
	assert.Equal(t, 42, val, "unexpected value")
	assert.Equal(t, 1, ttl.Len(), "unexpected cache length")

	assert.True(t, ttl.Remove("alpha"), "expected successful removal")
	assert.Equal(t, 0, ttl.Len(), "expected empty cache after removal")

	_, ok, expired = ttl.Get("alpha")
	assert.False(t, ok, "expected cache miss after removal")
	assert.False(t, expired, "expected non-expired miss after removal")
}

func TestTTLExpiration(t *testing.T) {
	t.Parallel()

	ttl := cache.NewTTL[string, int](10 * time.Millisecond)
	require.NotNil(t, ttl, "expected cache instance")

	ttl.Add("ephemeral", 7)
	time.Sleep(20 * time.Millisecond)

	_, ok, expired := ttl.Get("ephemeral")
	assert.False(t, ok, "expected cache miss for expired entry")
	assert.True(t, expired, "expected expired entry")
}

func TestTTLEvictCallback(t *testing.T) {
	t.Parallel()

	type evictEvent struct {
		key   string
		value int
	}

	events := make(chan evictEvent, 1)
	ttl := cache.NewTTL[string, int](
		time.Minute,
		cache.WithCapacity[string, int](1),
		cache.WithEvict[string, int](func(key string, value int) {
			events <- evictEvent{key: key, value: value}
		}),
	)
	require.NotNil(t, ttl, "expected cache instance")

	ttl.Add("first", 1)
	ttl.Add("second", 2) // should evict "first"

	select {
	case evt := <-events:
		assert.Equal(t, "first", evt.key, "unexpected evicted key")
		assert.Equal(t, 1, evt.value, "unexpected evicted value")
	default:
		require.Fail(t, "expected eviction event")
	}
}

func TestTTLDisabledWhenTTLNotPositive(t *testing.T) {
	t.Parallel()

	require.Nil(t, cache.NewTTL[string, int](0), "expected nil cache for zero ttl")
	require.Nil(t, cache.NewTTL[string, int](-time.Minute), "expected nil cache for negative ttl")
}

package cache

import (
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

// TTL wraps hashicorp's expirable LRU with nil-safe helpers and option hooks so
// services don't have to repeat boilerplate on every cache.
type TTL[K comparable, V any] struct {
	store *expirable.LRU[K, V]
}

// Options tweak TTL cache construction.
type Options[K comparable, V any] struct {
	capacity int
	onEvict  func(key K, value V)
}

// WithCapacity caps the number of live entries before LRU eviction.
func WithCapacity[K comparable, V any](size int) func(*Options[K, V]) {
	if size < 0 {
		size = 0
	}

	return func(opts *Options[K, V]) {
		opts.capacity = size
	}
}

// WithEvict installs a callback fired whenever an entry is evicted.
func WithEvict[K comparable, V any](cb func(key K, value V)) func(*Options[K, V]) {
	return func(opts *Options[K, V]) {
		opts.onEvict = cb
	}
}

// NewTTL constructs a TTL cache with the provided lifespan. ttl <= 0 disables
// caching and returns nil.
func NewTTL[K comparable, V any](ttl time.Duration, opts ...func(*Options[K, V])) *TTL[K, V] {
	if ttl <= 0 {
		return nil
	}

	var cfg Options[K, V]
	for _, opt := range opts {
		opt(&cfg)
	}

	var evict func(key K, value V)
	if cfg.onEvict != nil {
		evict = cfg.onEvict
	}

	return &TTL[K, V]{
		store: expirable.NewLRU[K, V](cfg.capacity, evict, ttl),
	}
}

// Add stores value under key, ignoring nil caches.
func (c *TTL[K, V]) Add(key K, value V) {
	if c == nil || c.store == nil {
		return
	}

	c.store.Add(key, value)
}

// Get returns the cached value, a hit flag, and whether an expired entry was
// purged during the lookup.
func (c *TTL[K, V]) Get(key K) (V, bool, bool) {
	var zero V
	if c == nil || c.store == nil {
		return zero, false, false
	}

	value, ok := c.store.Get(key)
	if ok {
		return value, true, false
	}

	return zero, false, c.store.Remove(key)
}

// Remove deletes key if present and reports whether it existed.
func (c *TTL[K, V]) Remove(key K) bool {
	if c == nil || c.store == nil {
		return false
	}

	return c.store.Remove(key)
}

// Len reports the live entry count.
func (c *TTL[K, V]) Len() int {
	if c == nil || c.store == nil {
		return 0
	}

	return c.store.Len()
}

package ndp

import (
	"net"
	"net/netip"
	"time"

	"github.com/jkoelker/ipv6relayd/pkg/cache"
	"github.com/jkoelker/ipv6relayd/pkg/netutil"
)

// targetCache tracks recently seen NDP targets and their group memberships using an expirable LRU.
type targetCache struct {
	cache *cache.TTL[string, targetEntry]
}

func newTargetCache(ttl time.Duration, onEvict func(string)) *targetCache {
	if ttl <= 0 {
		ttl = defaultTargetCacheTTL
	}

	var opts []func(*cache.Options[string, targetEntry])
	if onEvict != nil {
		opts = append(opts, cache.WithEvict[string, targetEntry](func(key string, _ targetEntry) {
			onEvict(key)
		}))
	}

	return &targetCache{
		cache: cache.NewTTL[string, targetEntry](ttl, opts...),
	}
}

func (c *targetCache) record(target net.IP, hostIP net.IP, downstreamName string, now time.Time) bool {
	if c == nil || c.cache == nil {
		return false
	}

	key, ok := ipToKey(target)
	if !ok {
		return false
	}

	entry := targetEntry{
		iface:      downstreamName,
		lastSeen:   now,
		lastHostIP: cloneHostHint(hostIP),
	}

	if entry.lastHostIP == nil {
		if prev, exists, _ := c.cache.Get(key); exists && prev.lastHostIP != nil {
			entry.lastHostIP = netutil.CloneAddr(prev.lastHostIP)
		}
	}

	c.cache.Add(key, entry)

	return true
}

func (c *targetCache) refresh(addr netip.Addr, now time.Time) (string, bool) {
	if c == nil || c.cache == nil {
		return "", false
	}

	key := addr.String()

	entry, ok, expired := c.cache.Get(key)
	if !ok {
		return "", expired
	}

	entry.lastSeen = now
	c.cache.Add(key, entry)

	return entry.iface, false
}

func (c *targetCache) hostHint(target net.IP) net.IP {
	if c == nil || c.cache == nil {
		return nil
	}

	key, ok := ipToKey(target)
	if !ok {
		return nil
	}

	entry, exists, _ := c.cache.Get(key)
	if !exists || entry.lastHostIP == nil {
		return nil
	}

	return netutil.CloneAddr(entry.lastHostIP)
}

func (c *targetCache) seed(key string, entry targetEntry) {
	if c == nil || c.cache == nil || key == "" {
		return
	}

	c.cache.Add(key, entry)
}

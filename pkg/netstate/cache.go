package netstate

import (
	"net"
	"sync"

	"github.com/jkoelker/ipv6relayd/pkg/netutil"
)

// LinkLocalCache stores discovered link-local addresses keyed by interface name.
// Entries are cloned on lookup/store so callers can mutate the returned IP
// without affecting the cache.
type LinkLocalCache struct {
	mu      sync.RWMutex
	byName  map[string]cachedLinkLocal
	byIndex map[int]string
}

type cachedLinkLocal struct {
	ip      net.IP
	ifIndex int
}

// NewLinkLocalCache builds an empty cache instance.
func NewLinkLocalCache() *LinkLocalCache {
	return &LinkLocalCache{
		byName:  make(map[string]cachedLinkLocal),
		byIndex: make(map[int]string),
	}
}

// Lookup returns a cloned link-local address for the provided interface name.
func (c *LinkLocalCache) Lookup(name string) net.IP {
	if c == nil || name == "" {
		return nil
	}

	c.mu.RLock()
	entry, ok := c.byName[name]
	c.mu.RUnlock()
	if !ok || entry.ip == nil {
		return nil
	}

	return netutil.CloneAddr(entry.ip)
}

// Store saves the provided link-local address under the interface name/index.
func (c *LinkLocalCache) Store(name string, ifIndex int, ip net.IP) {
	if c == nil || name == "" || ip == nil {
		return
	}

	clone := netutil.CloneAddr(ip)
	c.mu.Lock()
	c.byName[name] = cachedLinkLocal{ip: clone, ifIndex: ifIndex}
	if ifIndex != 0 {
		c.byIndex[ifIndex] = name
	}
	c.mu.Unlock()
}

// InvalidateName drops a cached entry associated with the provided name.
func (c *LinkLocalCache) InvalidateName(name string) {
	if c == nil || name == "" {
		return
	}

	c.mu.Lock()
	if entry, ok := c.byName[name]; ok && entry.ifIndex != 0 {
		delete(c.byIndex, entry.ifIndex)
	}
	delete(c.byName, name)
	c.mu.Unlock()
}

// InvalidateIndex drops a cached entry associated with the provided index.
func (c *LinkLocalCache) InvalidateIndex(index int) {
	if c == nil || index == 0 {
		return
	}

	c.mu.Lock()
	name, ok := c.byIndex[index]
	if ok {
		delete(c.byIndex, index)
		delete(c.byName, name)
	}
	c.mu.Unlock()
}

// Clear removes all cached entries.
func (c *LinkLocalCache) Clear() {
	if c == nil {
		return
	}

	c.mu.Lock()
	for k := range c.byName {
		delete(c.byName, k)
	}
	for k := range c.byIndex {
		delete(c.byIndex, k)
	}
	c.mu.Unlock()
}

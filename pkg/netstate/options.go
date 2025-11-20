package netstate

import "net"

// interfaceResolver centralizes interface address discovery configuration.
type interfaceResolver struct {
	interfaceAddrs func(*net.Interface) ([]net.Addr, error)
}

func (r *interfaceResolver) configureInterfaceAddrs(fn func(*net.Interface) ([]net.Addr, error)) {
	r.interfaceAddrs = fn
	if r.interfaceAddrs == nil {
		r.interfaceAddrs = SystemInterfaceAddrs
	}
}

func (r *interfaceResolver) resolveInterfaceAddrs(ifc *net.Interface) ([]net.Addr, error) {
	if r.interfaceAddrs == nil {
		return nil, ErrInterfaceAddressResolverUnset
	}

	return r.interfaceAddrs(ifc)
}

// Options configure optional behaviors shared among netstate helpers.
type Options struct {
	interfaceAddrs func(*net.Interface) ([]net.Addr, error)
	hintsFilter    func(net.IP) bool
	hintsInitial   map[string][]net.IP
	linkLocalCache *LinkLocalCache
}

func applyOptions(opts []func(*Options)) Options {
	var cfg Options

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		opt(&cfg)
	}

	return cfg
}

// WithInterfaceAddrsFunc overrides the interface address discovery function.
func WithInterfaceAddrsFunc(fn func(*net.Interface) ([]net.Addr, error)) func(*Options) {
	return func(o *Options) {
		o.interfaceAddrs = fn
	}
}

// WithLinkLocalCache injects the shared link-local cache used by Link.
func WithLinkLocalCache(cache *LinkLocalCache) func(*Options) {
	return func(o *Options) {
		o.linkLocalCache = cache
	}
}

// WithHintsFilter overrides the IP filter used by Hints.
func WithHintsFilter(fn func(net.IP) bool) func(*Options) {
	return func(o *Options) {
		o.hintsFilter = fn
	}
}

// WithInitialHints seeds Hints with the provided map.
func WithInitialHints(initial map[string][]net.IP) func(*Options) {
	return func(o *Options) {
		o.hintsInitial = initial
	}
}

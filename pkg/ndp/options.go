package ndp

import (
	"log/slog"
	"net"

	"github.com/jkoelker/ipv6relayd/pkg/iface"
	"github.com/jkoelker/ipv6relayd/pkg/ifmon"
	"github.com/jkoelker/ipv6relayd/pkg/netstate"
	"github.com/jkoelker/ipv6relayd/pkg/netutil"
)

// Options captures optional dependencies for the NDP service.
type Options struct {
	Logger                *slog.Logger
	InterfaceManager      *iface.Manager
	InterfaceAddrs        func(*net.Interface) ([]net.Addr, error)
	NeighborResolver      func(*net.Interface, net.IP) (net.HardwareAddr, error)
	AddressHints          map[string][]net.IP
	LinkLocalCache        *netstate.LinkLocalCache
	InterfaceEvents       <-chan ifmon.InterfaceEvent
	InterfaceEventsCancel func()
}

// DefaultOptions returns a struct populated with the standard NDP defaults.
func DefaultOptions() Options {
	return Options{
		Logger:                slog.New(slog.DiscardHandler).With("component", "ndp"),
		InterfaceAddrs:        netstate.SystemInterfaceAddrs,
		NeighborResolver:      defaultNeighborHardware,
		InterfaceEventsCancel: func() {},
	}
}

func (o *Options) apply(opts []func(*Options)) {
	for _, opt := range opts {
		if opt != nil {
			opt(o)
		}
	}
}

func (o *Options) finalize() {
	if o.InterfaceAddrs == nil {
		o.InterfaceAddrs = netstate.SystemInterfaceAddrs
	}
	if o.NeighborResolver == nil {
		o.NeighborResolver = defaultNeighborHardware
	}
	if o.InterfaceEventsCancel == nil {
		o.InterfaceEventsCancel = func() {}
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler).With("component", "ndp")
	}
}

// WithNeighborResolver overrides neighbor hardware resolution (used in tests).
func WithNeighborResolver(resolver func(*net.Interface, net.IP) (net.HardwareAddr, error)) func(*Options) {
	return func(o *Options) {
		if resolver != nil {
			o.NeighborResolver = resolver
		}
	}
}

// WithInterfaceAddrs overrides interface address resolution (used in tests).
func WithInterfaceAddrs(resolver func(*net.Interface) ([]net.Addr, error)) func(*Options) {
	return func(o *Options) {
		if resolver != nil {
			o.InterfaceAddrs = resolver
		}
	}
}

// WithInterfaceManager injects a custom interface manager (used in tests).
func WithInterfaceManager(manager *iface.Manager) func(*Options) {
	return func(o *Options) {
		if manager != nil {
			o.InterfaceManager = manager
		}
	}
}

// WithAddressHints seeds initial address hints (used in tests).
func WithAddressHints(hints map[string][]net.IP) func(*Options) {
	return func(o *Options) {
		o.AddressHints = cloneAddressHints(hints)
	}
}

// WithLinkLocalCache injects the shared link-local cache used by the service.
func WithLinkLocalCache(cache *netstate.LinkLocalCache) func(*Options) {
	return func(o *Options) {
		o.LinkLocalCache = cache
	}
}

// WithLogger sets the logger for the NDP service.
func WithLogger(logger *slog.Logger) func(*Options) {
	return func(o *Options) {
		if logger != nil {
			o.Logger = logger
		}
	}
}

// WithInterfaceEvents injects the shared interface event subscription.
func WithInterfaceEvents(events <-chan ifmon.InterfaceEvent, cancel func()) func(*Options) {
	return func(o *Options) {
		o.InterfaceEvents = events
		if cancel != nil {
			o.InterfaceEventsCancel = cancel
		} else {
			o.InterfaceEventsCancel = func() {}
		}
	}
}

// cloneAddressHints deep-copies the address-hints map to avoid sharing slices.
func cloneAddressHints(addrs map[string][]net.IP) map[string][]net.IP {
	if len(addrs) == 0 {
		return nil
	}

	cloned := make(map[string][]net.IP, len(addrs))
	for ifName, hints := range addrs {
		out := make([]net.IP, 0, len(hints))
		for _, ip := range hints {
			out = append(out, netutil.CloneAddr(ip))
		}
		cloned[ifName] = out
	}

	return cloned
}

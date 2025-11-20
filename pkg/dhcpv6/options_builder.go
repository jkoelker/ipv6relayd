package dhcpv6

import (
	"log/slog"
	"net"
	"time"

	"github.com/insomniacslk/dhcp/rfc1035label"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/iface"
	"github.com/jkoelker/ipv6relayd/pkg/ifmon"
	"github.com/jkoelker/ipv6relayd/pkg/netstate"
	"github.com/jkoelker/ipv6relayd/pkg/netutil"
)

// Options captures the optional dependencies for the DHCPv6 service.
type Options struct {
	Logger                *slog.Logger
	InterfaceEvents       <-chan ifmon.InterfaceEvent
	InterfaceEventsCancel func()
	InterfaceManager      *iface.Manager

	UpstreamInterface    *config.InterfaceConfig
	DownstreamInterfaces []config.InterfaceConfig
	ConfigOverride       *config.DHCPv6Config

	DNSOverride     []net.IP
	DNSSearchLabels *rfc1035label.Labels
	InitialHints    map[string][]net.IP

	InterfaceAddrs func(*net.Interface) ([]net.Addr, error)
	LinkLocals     *netstate.Link
	LinkLocalCache *netstate.LinkLocalCache

	UpstreamAddr     *net.UDPAddr
	UpstreamResolver upstreamResolverFunc
	TransactionTTL   time.Duration
}

// DefaultOptions returns a struct populated with the standard service defaults.
func DefaultOptions() Options {
	return Options{
		Logger:                slog.New(slog.DiscardHandler).With("component", "dhcpv6"),
		InterfaceAddrs:        netstate.SystemInterfaceAddrs,
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
	if o.InterfaceEventsCancel == nil {
		o.InterfaceEventsCancel = func() {}
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler).With("component", "dhcpv6")
	}
}

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

func WithInterfaceManager(mgr *iface.Manager) func(*Options) {
	return func(o *Options) {
		if mgr != nil {
			o.InterfaceManager = mgr
		}
	}
}

func WithUpstreamInterface(cfg config.InterfaceConfig) func(*Options) {
	clone := cfg

	return func(o *Options) {
		o.UpstreamInterface = &clone
	}
}

func WithDownstreamInterfaces(cfgs ...config.InterfaceConfig) func(*Options) {
	clones := append([]config.InterfaceConfig(nil), cfgs...)

	return func(o *Options) {
		o.DownstreamInterfaces = clones
	}
}

func WithLogger(logger *slog.Logger) func(*Options) {
	return func(o *Options) {
		if logger != nil {
			o.Logger = logger.With("component", "dhcpv6")
		}
	}
}

func WithDNSOverride(ips []net.IP) func(*Options) {
	clone := netutil.CloneSlice(ips)

	return func(o *Options) {
		o.DNSOverride = clone
	}
}

func WithDNSSearchLabels(labels *rfc1035label.Labels) func(*Options) {
	var clone *rfc1035label.Labels
	if labels != nil {
		clone = &rfc1035label.Labels{Labels: append([]string(nil), labels.Labels...)}
	}

	return func(o *Options) {
		o.DNSSearchLabels = clone
	}
}

func WithAddressHints(hints map[string][]net.IP) func(*Options) {
	cloned := cloneAddressHints(hints)

	return func(o *Options) {
		o.InitialHints = cloned
	}
}

func WithInterfaceAddrs(fn func(*net.Interface) ([]net.Addr, error)) func(*Options) {
	return func(o *Options) {
		if fn != nil {
			o.InterfaceAddrs = fn
		}
	}
}

func WithLinkLocals(linkLocals *netstate.Link) func(*Options) {
	return func(o *Options) {
		o.LinkLocals = linkLocals
	}
}

func WithConfig(cfg config.DHCPv6Config) func(*Options) {
	clone := cfg

	return func(o *Options) {
		o.ConfigOverride = &clone
	}
}

func WithUpstream(addr *net.UDPAddr) func(*Options) {
	clone := cloneUDPAddr(addr)

	return func(o *Options) {
		o.UpstreamAddr = clone
	}
}

func WithUpstreamResolver(fn upstreamResolverFunc) func(*Options) {
	return func(o *Options) {
		if fn != nil {
			o.UpstreamResolver = fn
		}
	}
}

// WithTransactionTTL overrides the default transaction cache TTL; primarily for tests.
func WithTransactionTTL(ttl time.Duration) func(*Options) {
	return func(o *Options) {
		if ttl > 0 {
			o.TransactionTTL = ttl
		}
	}
}

// WithLinkLocalCache injects the shared link-local cache into the service.
func WithLinkLocalCache(cache *netstate.LinkLocalCache) func(*Options) {
	return func(o *Options) {
		o.LinkLocalCache = cache
	}
}

func cloneAddressHints(addrs map[string][]net.IP) map[string][]net.IP {
	if len(addrs) == 0 {
		return nil
	}

	out := make(map[string][]net.IP, len(addrs))
	for key, value := range addrs {
		if len(value) == 0 {
			continue
		}
		clone := make([]net.IP, len(value))
		for i, ip := range value {
			clone[i] = netutil.CloneAddr(ip)
		}
		out[key] = clone
	}

	if len(out) == 0 {
		return nil
	}

	return out
}

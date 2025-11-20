package ra

import (
	"context"
	"log/slog"
	"net"

	"golang.org/x/net/ipv6"

	"github.com/jkoelker/ipv6relayd/pkg/ifmon"
	"github.com/jkoelker/ipv6relayd/pkg/netstate"
)

// Options captures optional dependencies for the RA service.
type Options struct {
	Logger                *slog.Logger
	InterfaceEvents       <-chan ifmon.InterfaceEvent
	InterfaceEventsCancel func()
	LinkLocalCache        *netstate.LinkLocalCache
	ForwardToUpstream     func(context.Context, *ipv6.PacketConn, *net.Interface, []byte) error
	DHCPv6Enabled         bool
}

// DefaultOptions returns a struct populated with safe defaults.
func DefaultOptions() Options {
	return Options{
		Logger:                slog.New(slog.DiscardHandler).With("component", "ra"),
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
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler).With("component", "ra")
	}
	if o.InterfaceEventsCancel == nil {
		o.InterfaceEventsCancel = func() {}
	}
}

// WithInterfaceEvents injects the shared interface event subscription. cancel defaults to a no-op when nil.
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

// WithLinkLocalCache injects the shared link-local cache used by the service.
func WithLinkLocalCache(cache *netstate.LinkLocalCache) func(*Options) {
	return func(o *Options) {
		o.LinkLocalCache = cache
	}
}

// WithForwardToUpstream overrides the upstream forwarding path (used by tests).
func WithForwardToUpstream(
	handler func(context.Context, *ipv6.PacketConn, *net.Interface, []byte) error,
) func(*Options) {
	return func(o *Options) {
		if handler != nil {
			o.ForwardToUpstream = handler
		}
	}
}

// WithLogger overrides the logger used by the service.
func WithLogger(logger *slog.Logger) func(*Options) {
	return func(o *Options) {
		if logger != nil {
			o.Logger = logger.With("component", "ra")
		}
	}
}

// WithDHCPv6Enabled informs the RA service whether DHCPv6 relay is enabled so it can set M/O flags consistently.
func WithDHCPv6Enabled(enabled bool) func(*Options) {
	return func(o *Options) {
		o.DHCPv6Enabled = enabled
	}
}

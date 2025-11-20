package ifmon

import "log/slog"

// WithLogger overrides the logger used for diagnostic output.
func WithLogger(logger *slog.Logger) func(*Monitor) {
	return func(m *Monitor) {
		m.log = logger
	}
}

// WithQueueSize overrides the internal netlink subscription queue size.
func WithQueueSize(size int) func(*Monitor) {
	return func(m *Monitor) {
		if size > 0 {
			m.queueSize = size
		}
	}
}

// WithSubscriberQueue overrides the per-subscriber buffer size.
func WithSubscriberQueue(size int) func(*Monitor) {
	return func(m *Monitor) {
		if size > 0 {
			m.subscriberQueueLen = size
		}
	}
}

// WithLinkSubscribe injects a custom netlink.LinkSubscribe implementation, useful for tests.
func WithLinkSubscribe(fn linkSubscribeFunc) func(*Monitor) {
	return func(m *Monitor) {
		if fn != nil {
			m.linkSubscribe = fn
		}
	}
}

// WithAddrSubscribe injects a custom netlink.AddrSubscribe implementation, useful for tests.
func WithAddrSubscribe(fn addrSubscribeFunc) func(*Monitor) {
	return func(m *Monitor) {
		if fn != nil {
			m.addrSubscribe = fn
		}
	}
}

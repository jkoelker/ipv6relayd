package ifmon

import (
	"context"
	"fmt"

	"github.com/vishvananda/netlink"
)

// LinkHandler consumes link updates forwarded by the shared monitor.
type LinkHandler func(context.Context, netlink.LinkUpdate)

// AddrHandler consumes address updates forwarded by the shared monitor.
type AddrHandler func(context.Context, netlink.AddrUpdate)

// Watcher coordinates a subscription to the shared interface monitor and
// dispatches link and address updates to the provided handlers.
type Watcher struct {
	monitor *Monitor
}

// NewWatcher builds a Watcher bound to the provided Monitor.
func NewWatcher(m *Monitor) *Watcher {
	return &Watcher{monitor: m}
}

// Start ensures the underlying monitor is running, subscribes to updates, and
// dispatches them to the supplied handlers until ctx is canceled. Handlers may
// be nil when updates are not needed.
func (w *Watcher) Start(
	ctx context.Context,
	linkHandler LinkHandler,
	addrHandler AddrHandler,
) error {
	if ctx == nil {
		return ErrNilContext
	}
	if w == nil || w.monitor == nil {
		return ErrNotConfigured
	}
	if err := w.monitor.Run(ctx); err != nil {
		return fmt.Errorf("run interface monitor: %w", err)
	}
	sub, err := w.monitor.Subscribe(ctx)
	if err != nil {
		return fmt.Errorf("subscribe interface monitor: %w", err)
	}

	go w.consume(ctx, sub, linkHandler, addrHandler)

	return nil
}

func (w *Watcher) consume(
	ctx context.Context,
	sub *Subscription,
	linkHandler LinkHandler,
	addrHandler AddrHandler,
) {
	defer sub.Close()

	for {
		select {
		case <-ctx.Done():
			return
		case update, ok := <-sub.LinkUpdates:
			if !ok {
				return
			}
			if linkHandler != nil {
				linkHandler(ctx, update)
			}
		case update, ok := <-sub.AddressUpdates:
			if !ok {
				return
			}
			if addrHandler != nil {
				addrHandler(ctx, update)
			}
		}
	}
}

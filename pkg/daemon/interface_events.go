package daemon

import (
	"log/slog"
	"sync"

	"github.com/jkoelker/ipv6relayd/pkg/ifmon"
)

const interfaceEventBuffer = 16

type interfaceEventBus struct {
	mu   sync.RWMutex
	subs map[uint64]chan ifmon.InterfaceEvent
	next uint64
	log  *slog.Logger
}

func newInterfaceEventBus(logger *slog.Logger) *interfaceEventBus {
	return &interfaceEventBus{
		subs: make(map[uint64]chan ifmon.InterfaceEvent),
		log:  logger,
	}
}

func (b *interfaceEventBus) Subscribe() (<-chan ifmon.InterfaceEvent, func()) {
	if b == nil {
		return nil, func() {}
	}

	events := make(chan ifmon.InterfaceEvent, interfaceEventBuffer)

	b.mu.Lock()
	ident := b.next
	b.next++
	b.subs[ident] = events
	b.mu.Unlock()

	cancel := func() {
		b.mu.Lock()
		defer b.mu.Unlock()

		if subscriber, ok := b.subs[ident]; ok {
			delete(b.subs, ident)
			close(subscriber)
		}
	}

	return events, cancel
}

func (b *interfaceEventBus) Publish(event ifmon.InterfaceEvent) {
	if b == nil {
		return
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	for id, sub := range b.subs {
		select {
		case sub <- event:
		default:
			if b.log != nil {
				b.log.Debug("dropping interface event due to slow subscriber", "subscriber", id)
			}
		}
	}
}

func (b *interfaceEventBus) Close() {
	if b == nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	for id, sub := range b.subs {
		close(sub)
		delete(b.subs, id)
	}
}

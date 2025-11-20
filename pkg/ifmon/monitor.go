package ifmon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/vishvananda/netlink"
)

var (
	// ErrNilContext indicates that a nil context was passed to Run or Subscribe.
	ErrNilContext = errors.New("context must not be nil")

	// ErrNotConfigured signals that the monitor dependency was not injected.
	ErrNotConfigured = errors.New("interface monitor not configured")
)

const (
	defaultQueueSize       = 16
	defaultSubscriberQueue = 16
)

type linkSubscribeFunc func(chan<- netlink.LinkUpdate, <-chan struct{}) error
type addrSubscribeFunc func(chan<- netlink.AddrUpdate, <-chan struct{}) error

// Monitor fan-outs netlink link and address updates to any interested subscribers.
type Monitor struct {
	linkSubscribe linkSubscribeFunc
	addrSubscribe addrSubscribeFunc

	queueSize          int
	subscriberQueueLen int

	log *slog.Logger

	startMu sync.Mutex
	started bool

	subscribersMu sync.RWMutex
	subscribers   map[uint64]*subscription
	nextID        uint64
}

// New builds a Monitor with the provided options.
func New(opts ...func(*Monitor)) *Monitor {
	monitor := &Monitor{
		linkSubscribe:      netlink.LinkSubscribe,
		addrSubscribe:      netlink.AddrSubscribe,
		queueSize:          defaultQueueSize,
		subscriberQueueLen: defaultSubscriberQueue,
		subscribers:        make(map[uint64]*subscription),
	}

	for _, opt := range opts {
		opt(monitor)
	}

	if monitor.log == nil {
		monitor.log = slog.New(slog.DiscardHandler)
	}

	return monitor
}

// Run starts the underlying netlink subscriptions if they are not already running.
func (m *Monitor) Run(ctx context.Context) error {
	if ctx == nil {
		return ErrNilContext
	}

	m.startMu.Lock()
	defer m.startMu.Unlock()

	if m.started {
		return nil
	}

	linkCh := make(chan netlink.LinkUpdate, m.queueSize)
	addrCh := make(chan netlink.AddrUpdate, m.queueSize)
	done := make(chan struct{})

	if err := m.linkSubscribe(linkCh, done); err != nil {
		close(done)

		return fmt.Errorf("subscribe link updates: %w", err)
	}

	if err := m.addrSubscribe(addrCh, done); err != nil {
		close(done)

		return fmt.Errorf("subscribe address updates: %w", err)
	}

	go func() {
		<-ctx.Done()
		close(done)
		m.shutdownSubscribers()
	}()

	go m.forwardLinks(ctx, linkCh)
	go m.forwardAddresses(ctx, addrCh)

	m.started = true

	return nil
}

// Subscribe registers a listener for interface updates. The returned Subscription
// must be closed by the caller to avoid leaks. The subscription automatically
// ends when ctx is canceled.
func (m *Monitor) Subscribe(ctx context.Context) (*Subscription, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("subscribe context closed: %w", ctx.Err())
	default:
	}

	linkCh := make(chan netlink.LinkUpdate, m.subscriberQueueLen)
	addrCh := make(chan netlink.AddrUpdate, m.subscriberQueueLen)

	sub := &subscription{
		linkCh: linkCh,
		addrCh: addrCh,
	}

	m.subscribersMu.Lock()
	sub.id = m.nextID
	m.nextID++
	m.subscribers[sub.id] = sub
	m.subscribersMu.Unlock()

	go func() {
		<-ctx.Done()
		m.removeSubscriber(sub.id)
	}()

	return &Subscription{
		LinkUpdates:    linkCh,
		AddressUpdates: addrCh,
		cancel: func() {
			m.removeSubscriber(sub.id)
		},
	}, nil
}

func (m *Monitor) forwardLinks(ctx context.Context, updates <-chan netlink.LinkUpdate) {
	for {
		select {
		case <-ctx.Done():
			return
		case update, ok := <-updates:
			if !ok {
				return
			}

			m.broadcastLink(update)
		}
	}
}

func (m *Monitor) forwardAddresses(ctx context.Context, updates <-chan netlink.AddrUpdate) {
	for {
		select {
		case <-ctx.Done():
			return
		case update, ok := <-updates:
			if !ok {
				return
			}

			m.broadcastAddress(update)
		}
	}
}

func (m *Monitor) broadcastLink(update netlink.LinkUpdate) {
	m.subscribersMu.RLock()
	defer m.subscribersMu.RUnlock()

	for _, sub := range m.subscribers {
		select {
		case sub.linkCh <- update:
		default:
			m.log.Debug("dropping link update due to subscriber backlog", "subscriber", sub.id)
		}
	}
}

func (m *Monitor) broadcastAddress(update netlink.AddrUpdate) {
	m.subscribersMu.RLock()
	defer m.subscribersMu.RUnlock()

	for _, sub := range m.subscribers {
		select {
		case sub.addrCh <- update:
		default:
			m.log.Debug("dropping address update due to subscriber backlog", "subscriber", sub.id)
		}
	}
}

func (m *Monitor) removeSubscriber(id uint64) {
	m.subscribersMu.Lock()
	sub, ok := m.subscribers[id]
	if ok {
		delete(m.subscribers, id)
	}
	m.subscribersMu.Unlock()

	if !ok {
		return
	}

	sub.closeMu.Do(func() {
		close(sub.linkCh)
		close(sub.addrCh)
	})
}

func (m *Monitor) shutdownSubscribers() {
	m.subscribersMu.Lock()
	subs := make([]*subscription, 0, len(m.subscribers))
	for _, sub := range m.subscribers {
		subs = append(subs, sub)
	}
	m.subscribers = make(map[uint64]*subscription)
	m.subscribersMu.Unlock()

	for _, sub := range subs {
		sub.closeMu.Do(func() {
			close(sub.linkCh)
			close(sub.addrCh)
		})
	}
}

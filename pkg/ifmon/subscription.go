package ifmon

import (
	"sync"

	"github.com/vishvananda/netlink"
)

// Subscription delivers interface updates to a consumer.
type Subscription struct {
	LinkUpdates    <-chan netlink.LinkUpdate
	AddressUpdates <-chan netlink.AddrUpdate

	cancel    func()
	closeOnce sync.Once
}

type subscription struct {
	id      uint64
	linkCh  chan netlink.LinkUpdate
	addrCh  chan netlink.AddrUpdate
	closeMu sync.Once
}

// Close terminates the subscription and releases its resources.
func (s *Subscription) Close() {
	s.closeOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
	})
}

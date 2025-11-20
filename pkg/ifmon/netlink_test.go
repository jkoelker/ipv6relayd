package ifmon_test

import (
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/jkoelker/ipv6relayd/pkg/ifmon"
	"github.com/jkoelker/ipv6relayd/pkg/testutil"
)

type stubNetlink struct {
	linkCh chan<- netlink.LinkUpdate
	addrCh chan<- netlink.AddrUpdate

	linkErr error
	addrErr error

	linkDone <-chan struct{}
	addrDone <-chan struct{}
}

func (s *stubNetlink) linkSubscribe(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error {
	if s.linkErr != nil {
		return s.linkErr
	}

	s.linkCh = ch
	// capture done channel for tests needing to assert shutdown.
	s.linkDone = done

	return nil
}

func (s *stubNetlink) addrSubscribe(ch chan<- netlink.AddrUpdate, done <-chan struct{}) error {
	if s.addrErr != nil {
		return s.addrErr
	}

	s.addrCh = ch
	s.addrDone = done

	return nil
}

func newMonitorWithStub(t *testing.T, stub *stubNetlink) *ifmon.Monitor {
	t.Helper()

	return ifmon.New(
		ifmon.WithLogger(testutil.LoggerFromTB(t)),
		ifmon.WithLinkSubscribe(stub.linkSubscribe),
		ifmon.WithAddrSubscribe(stub.addrSubscribe),
	)
}

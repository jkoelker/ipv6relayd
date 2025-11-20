package ndp_test

import "github.com/jkoelker/ipv6relayd/pkg/ifmon"

func newTestInterfaceEvents() (<-chan ifmon.InterfaceEvent, func()) {
	ch := make(chan ifmon.InterfaceEvent)
	close(ch)

	return ch, func() {}
}

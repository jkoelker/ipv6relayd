package ndp

import (
	"context"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const neighEventBufferSize = 64

type neighSubscriber func(ch chan<- netlink.NeighUpdate, done <-chan struct{}) error

//nolint:gochecknoglobals // var for testing
var defaultNeighSubscribe neighSubscriber = netlink.NeighSubscribe

func (s *Service) startNeighborMonitor(ctx context.Context, upstreamIndex int, downstreams []*net.Interface) {
	subscribe := s.neighSubscribe
	if subscribe == nil {
		subscribe = defaultNeighSubscribe
	}

	neighCh := make(chan netlink.NeighUpdate, neighEventBufferSize)
	done := make(chan struct{})

	if err := subscribe(neighCh, done); err != nil {
		if s.log != nil {
			s.log.Warn("failed to subscribe to neighbor events", "err", err)
		}

		return
	}

	go func() {
		<-ctx.Done()
		close(done)
	}()

	go s.processNeighborEvents(ctx, neighCh, upstreamIndex, downstreams)
}

func (s *Service) processNeighborEvents(
	ctx context.Context,
	neighCh <-chan netlink.NeighUpdate,
	upstreamIndex int,
	downstreams []*net.Interface,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case update, ok := <-neighCh:
			if !ok {
				return
			}

			s.handleNeighborUpdate(update, upstreamIndex, downstreams)
		}
	}
}

func (s *Service) handleNeighborUpdate(
	update netlink.NeighUpdate,
	upstreamIndex int,
	downstreams []*net.Interface,
) {
	if update.LinkIndex != upstreamIndex {
		return
	}

	if update.Family != unix.AF_INET6 {
		return
	}

	if !isFailedOrIncomplete(update.State) {
		return
	}

	if update.IP == nil || !update.IP.IsGlobalUnicast() {
		return
	}

	if s.log != nil {
		s.log.Debug("neighbor failed on upstream, installing host routes",
			"target", update.IP,
			"state", neighStateString(update.State),
			"upstream_index", upstreamIndex)
	}

	upstream, err := s.ifaces.ByName(s.upstream.IfName)
	if err != nil {
		if s.log != nil {
			s.log.Debug("failed to lookup upstream for neighbor event", "err", err)
		}

		return
	}

	for _, downstream := range downstreams {
		s.trackTarget(update.IP, nil, downstream, upstream, nil)
	}
}

func isFailedOrIncomplete(state int) bool {
	return state&(netlink.NUD_FAILED|netlink.NUD_INCOMPLETE) != 0
}

func neighStateString(state int) string {
	switch {
	case state&netlink.NUD_FAILED != 0:
		return "FAILED"
	case state&netlink.NUD_INCOMPLETE != 0:
		return "INCOMPLETE"
	case state&netlink.NUD_REACHABLE != 0:
		return "REACHABLE"
	case state&netlink.NUD_STALE != 0:
		return "STALE"
	case state&netlink.NUD_DELAY != 0:
		return "DELAY"
	case state&netlink.NUD_PROBE != 0:
		return "PROBE"
	case state&netlink.NUD_PERMANENT != 0:
		return "PERMANENT"
	case state&netlink.NUD_NOARP != 0:
		return "NOARP"
	default:
		return "UNKNOWN"
	}
}

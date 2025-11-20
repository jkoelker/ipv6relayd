package ra

import (
	"context"

	"golang.org/x/net/ipv6"
)

func (s *Service) startInterfaceEvents(ctx context.Context, packetConn *ipv6.PacketConn) error {
	if s.ifaceEvents == nil {
		return ErrInterfaceEventsRequired
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-s.ifaceEvents:
				if !ok {
					return
				}
				s.refreshInterfaceState(packetConn, ev.Reason)
			}
		}
	}()

	return nil
}

func (s *Service) stopInterfaceEvents() {
	if s.ifaceEventsCancel != nil {
		s.ifaceEventsCancel()
		s.ifaceEventsCancel = nil
	}
}

func (s *Service) refreshInterfaceState(packetConn *ipv6.PacketConn, reason string) {
	s.ifaces.Flush()

	if err := s.refreshMulticast(packetConn); err != nil {
		s.log.Warn("failed to refresh multicast memberships", "reason", reason, "err", err)
	}
}

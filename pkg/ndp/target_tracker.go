package ndp

import (
	"net"
	"time"

	"golang.org/x/net/ipv6"
)

// trackTarget records the target in caches, host routes, and solicited-node joins.
func (s *Service) trackTarget(
	target net.IP,
	hostIP net.IP,
	downstream *net.Interface,
	upstream *net.Interface,
	packetConn *ipv6.PacketConn,
) {
	if !s.shouldTrackTarget(target, downstream, upstream, packetConn) {
		if s.log != nil {
			s.log.Debug("skip tracking target",
				"target", target,
				"link_local", target != nil && target.IsLinkLocalUnicast(),
				"downstream_nil", downstream == nil,
				"upstream_nil", upstream == nil,
				"packet_conn_nil", packetConn == nil)
		}

		return
	}

	if !s.recordTargetEntry(target, hostIP, downstream) {
		return
	}
	s.ensureHostRoute(target, downstream)
}

func (s *Service) shouldTrackTarget(
	target net.IP,
	downstream *net.Interface,
	upstream *net.Interface,
	packetConn *ipv6.PacketConn,
) bool {
	return target != nil &&
		!target.IsLinkLocalUnicast() &&
		downstream != nil &&
		upstream != nil &&
		packetConn != nil
}

func (s *Service) recordTargetEntry(target net.IP, hostIP net.IP, downstream *net.Interface) bool {
	if s.targetCache == nil {
		return false
	}

	return s.targetCache.record(target, hostIP, downstream.Name, time.Now())
}

func (s *Service) removeExpiredHostRoutes(keys []string) {
	if len(keys) == 0 {
		return
	}

	if s.routes != nil {
		s.routes.removeHostRoutes(keys)
	}
}

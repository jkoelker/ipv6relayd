package ndp

import (
	"errors"
	"fmt"
	"net"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"

	"github.com/jkoelker/ipv6relayd/pkg/config"
)

func (s *Service) forwardSolicitationToDownstream(
	packetConn *ipv6.PacketConn,
	msg *ndp.NeighborSolicitation,
	dst net.IP,
	downstream *net.Interface,
	src net.Addr,
) error {
	if downstream == nil {
		return nil
	}

	cfg, hasCfg := s.downstreamConfigs[downstream.Name]
	if hasCfg && cfg.Passive {
		return nil
	}

	target := s.selectSolicitationTarget(dst, msg)

	if actual := addrToIP(msg.TargetAddress); actual != nil && !actual.IsLinkLocalUnicast() {
		s.ensureHostRoute(actual, downstream)
	}

	if hasCfg {
		if err := s.ensureDownstreamLinkLocal(downstream, cfg, "NS forwarding"); err != nil {
			return err
		}
	}

	prepared, err := s.prepareNeighborSolicitation(msg, downstream, src)
	if err != nil {
		return err
	}

	ctrl := &ipv6.ControlMessage{
		IfIndex:  downstream.Index,
		HopLimit: multicastHopLimit,
	}
	addr := &net.IPAddr{IP: target}

	if _, err := packetConn.WriteTo(prepared, ctrl, addr); err != nil {
		s.handleWriteError(err)

		return fmt.Errorf("send downstream on %s: %w", downstream.Name, err)
	}

	return nil
}

func (s *Service) forwardSolicitationsToAll(
	packetConn *ipv6.PacketConn,
	msg *ndp.NeighborSolicitation,
	controlMessage *ipv6.ControlMessage,
	upstream *net.Interface,
	downstreams []*net.Interface,
	src net.Addr,
) error {
	target := addrToIP(msg.TargetAddress)
	if !s.shouldFloodTarget(target) {
		s.log.Debug("suppressing repeated solicitation flood", "target", target)

		return nil
	}

	s.triggerNeighborDiscovery(packetConn, target, controlMessage.IfIndex, upstream, downstreams)

	dst := controlMessage.Dst
	if dst == nil || dst.IsUnspecified() {
		dst = s.allNodesIP
	}

	return s.ForEachDownstream(downstreams, func(downstream *net.Interface) error {
		err := s.forwardSolicitationToDownstream(packetConn, msg, dst, downstream, src)
		if err != nil {
			if s.log != nil {
				ifaceName := "unknown"
				if downstream != nil {
					ifaceName = downstream.Name
				}
				s.log.Warn("failed to forward solicitation downstream", "iface", ifaceName, "err", err)
			}
		}

		return err
	})
}

func (s *Service) forwardAdvertisementToDownstream(
	packetConn *ipv6.PacketConn,
	msg *ndp.NeighborAdvertisement,
	controlMessage *ipv6.ControlMessage,
	downstream *net.Interface,
) error {
	if downstream == nil {
		return nil
	}

	cfg, hasCfg := s.downstreamConfigs[downstream.Name]
	if hasCfg && cfg.Passive {
		return nil
	}

	if hasCfg {
		if err := s.ensureDownstreamLinkLocal(downstream, cfg, "NA forwarding"); err != nil {
			return err
		}
	}

	prepared, err := s.prepareNeighborAdvertisement(msg, downstream)
	if err != nil {
		return err
	}

	target := controlMessage.Dst
	if target == nil || target.IsUnspecified() {
		target = s.allNodesIP
	}

	ctrl := &ipv6.ControlMessage{
		IfIndex:  downstream.Index,
		HopLimit: multicastHopLimit,
	}
	if _, err := packetConn.WriteTo(prepared, ctrl, &net.IPAddr{IP: target}); err != nil {
		s.handleWriteError(err)

		return fmt.Errorf("send downstream on %s: %w", downstream.Name, err)
	}

	return nil
}

func (s *Service) forwardAdvertisementToUpstream(
	packetConn *ipv6.PacketConn,
	msg *ndp.NeighborAdvertisement,
	controlMessage *ipv6.ControlMessage,
	upstream *net.Interface,
) error {
	if upstream == nil {
		return nil
	}

	prepared, err := s.prepareNeighborAdvertisement(msg, upstream)
	if err != nil {
		return err
	}

	target := controlMessage.Dst
	if target == nil || target.IsUnspecified() {
		target = s.allNodesIP
	}

	ctrl := &ipv6.ControlMessage{
		IfIndex:  upstream.Index,
		HopLimit: multicastHopLimit,
	}
	if _, err := packetConn.WriteTo(prepared, ctrl, &net.IPAddr{IP: target}); err != nil {
		s.handleWriteError(err)

		return fmt.Errorf("send upstream on %s: %w", upstream.Name, err)
	}

	return nil
}

func (s *Service) selectSolicitationTarget(dst net.IP, msg *ndp.NeighborSolicitation) net.IP {
	if dst == nil || dst.IsUnspecified() {
		return s.allNodesIP
	}

	if dst.IsMulticast() {
		return dst
	}

	if t := addrToIP(msg.TargetAddress); t != nil {
		if group := solicitedNodeMulticast(t); group != nil {
			return group
		}
	}

	return dst
}

func (s *Service) ensureDownstreamLinkLocal(
	downstream *net.Interface,
	cfg config.InterfaceConfig,
	context string,
) error {
	if downstream == nil {
		return nil
	}

	if _, err := s.resolveDownstreamLinkLocal(downstream, cfg); err != nil {
		if errors.Is(err, ErrNoLinkLocalAddress) {
			if s.log != nil {
				s.log.Debug("skip forwarding; downstream lacks link-local address", "iface", downstream.Name, "context", context)
			}

			return nil
		}

		return fmt.Errorf("resolve downstream link-local: %w", err)
	}

	return nil
}

package ndp

import (
	"fmt"
	"net"

	"golang.org/x/net/ipv6"

	"github.com/jkoelker/ipv6relayd/pkg/netutil"
)

func (s *Service) sendRedirect(
	packetConn *ipv6.PacketConn,
	payload []byte,
	iface *net.Interface,
	target net.IP,
	dest net.IP,
) error {
	if dest == nil || dest.IsUnspecified() {
		return ErrRedirectHostUnspecified
	}

	prepared, err := s.PrepareRedirect(payload, iface, s.resolveRedirectTargetHardware(target, iface))
	if err != nil {
		return err
	}

	ctrl := &ipv6.ControlMessage{IfIndex: iface.Index}

	if _, err := packetConn.WriteTo(prepared, ctrl, &net.IPAddr{IP: dest}); err != nil {
		s.handleWriteError(err)

		return fmt.Errorf("send redirect on %s: %w", iface.Name, err)
	}

	return nil
}

func (s *Service) resolveRedirectTargetHardware(target net.IP, iface *net.Interface) net.HardwareAddr {
	if target == nil || iface == nil {
		return nil
	}

	ifc := s.redirectLookupInterface(iface)

	if hardware := s.redirectNeighborHardware(ifc, target); len(hardware) > 0 {
		return hardware
	}

	return s.redirectFallbackHardware(ifc)
}

func (s *Service) redirectLookupInterface(iface *net.Interface) *net.Interface {
	if iface == nil {
		return nil
	}

	if cfg, ok := s.downstreamConfigs[iface.Name]; ok && cfg.Passive {
		if upstream, _, _ := s.lookupInterfaceByName(s.upstream.IfName); upstream != nil {
			return upstream
		}
	}

	return iface
}

func (s *Service) redirectNeighborHardware(iface *net.Interface, target net.IP) net.HardwareAddr {
	if iface == nil {
		return nil
	}

	hardware, err := s.neighborResolver(iface, target)
	if err != nil {
		s.log.Debug("failed to resolve neighbor hardware", "iface", iface.Name, "target", target, "err", err)
	}

	return hardware
}

func (s *Service) redirectFallbackHardware(iface *net.Interface) net.HardwareAddr {
	if iface == nil {
		return nil
	}

	// Only fall back to the provided interface's hardware when it is (or we can reasonably treat
	// it as the upstream side.
	if s.upstream.IfName != "" && iface.Name != s.upstream.IfName {
		return nil
	}

	// Heuristic: if upstream is unspecified and iface appears in static bindings, treat it as
	// downstream; otherwise upstream.
	if s.upstream.IfName == "" {
		for _, binding := range s.staticBindings {
			if binding.iface == iface.Name {
				return nil
			}
		}
	}

	return netutil.CloneAddr(iface.HardwareAddr)
}

// handleRedirect forwards ICMPv6 Redirect messages between upstream and downstreams.
func (s *Service) handleRedirect(
	packetConn *ipv6.PacketConn,
	payload []byte,
	controlMessage *ipv6.ControlMessage,
	_ net.IP,
	upstream *net.Interface,
	downstreamByIndex map[int]*net.Interface,
	downstreams []*net.Interface,
) error {
	if len(payload) < ndpRedirectHeaderLen {
		return ErrRedirectMessageTooShort
	}

	target := make(net.IP, net.IPv6len)
	copy(target, payload[8:24])
	dest := make(net.IP, net.IPv6len)
	copy(dest, payload[24:40])

	if controlMessage == nil || packetConn == nil {
		return nil
	}

	if s.redirectFromUpstream(packetConn, payload, controlMessage, upstream, downstreams, target, dest) {
		return nil
	}

	if s.redirectFromDownstream(packetConn, payload, controlMessage, upstream, downstreamByIndex, target, dest) {
		return nil
	}

	return nil
}

func (s *Service) redirectFromUpstream(
	packetConn *ipv6.PacketConn,
	payload []byte,
	controlMessage *ipv6.ControlMessage,
	upstream *net.Interface,
	downstreams []*net.Interface,
	target net.IP,
	dest net.IP,
) bool {
	if upstream == nil || controlMessage.IfIndex != upstream.Index {
		return false
	}

	for _, downstream := range downstreams {
		if downstream == nil {
			continue
		}

		if err := s.sendRedirect(packetConn, payload, downstream, target, dest); err != nil {
			s.log.Debug("failed to forward redirect downstream", "iface", downstream.Name, "err", err)
		}
	}

	return true
}

func (s *Service) redirectFromDownstream(
	packetConn *ipv6.PacketConn,
	payload []byte,
	controlMessage *ipv6.ControlMessage,
	upstream *net.Interface,
	downstreamByIndex map[int]*net.Interface,
	target net.IP,
	dest net.IP,
) bool {
	if upstream == nil {
		return false
	}

	if _, ok := downstreamByIndex[controlMessage.IfIndex]; !ok {
		return false
	}

	if err := s.sendRedirect(packetConn, payload, upstream, target, dest); err != nil {
		s.log.Debug("failed to forward redirect upstream", "err", err)
	}

	return true
}

// rewriteRedirectOptions updates link-layer options and reports which were present.
func rewriteRedirectOptions(
	payload []byte,
	sourceMAC, targetMAC net.HardwareAddr,
) (bool, bool, error) {
	var hasSource, hasTarget bool

	return hasSource, hasTarget, forEachNDPOption(payload, ndpRedirectHeaderLen, func(optType byte, option []byte) error {
		switch optType {
		case ndpOptSourceLL:
			hasSource = true
			overwriteLinkLayer(option, sourceMAC)
		case ndpOptTargetLL:
			hasTarget = true
			overwriteLinkLayer(option, targetMAC)
		}

		return nil
	})
}

func redirectTargetHardware(_ *net.Interface, targetHW net.HardwareAddr) net.HardwareAddr {
	if len(targetHW) > 0 {
		return netutil.CloneAddr(targetHW)
	}

	return nil
}

package ndp

import (
	"net"
	"time"

	"golang.org/x/net/ipv6"

	"github.com/jkoelker/ipv6relayd/pkg/config"
)

func (s *Service) shouldFloodTarget(target net.IP) bool {
	if target == nil {
		return true
	}

	key, ok := ipToKey(target)
	if !ok {
		return true
	}

	now := time.Now()

	s.probeMu.Lock()
	defer s.probeMu.Unlock()

	if last, exists := s.lastProbe[key]; exists && now.Sub(last) < s.probeCooldown {
		return false
	}

	s.lastProbe[key] = now

	return true
}

func (s *Service) triggerNeighborDiscovery(
	packetConn *ipv6.PacketConn,
	target net.IP,
	sourceIndex int,
	upstream *net.Interface,
	downstreams []*net.Interface,
) {
	if packetConn == nil || target == nil {
		return
	}

	s.sendProbes(packetConn, upstream, downstreams, target, sourceIndex)
}

func (s *Service) sendProbes(
	packetConn *ipv6.PacketConn,
	upstream *net.Interface,
	downstreams []*net.Interface,
	target net.IP,
	sourceIndex int,
) {
	if !allowNDPHint(target) {
		return
	}

	group := solicitedNodeMulticast(target)
	if group == nil {
		return
	}

	if upstream != nil {
		s.sendProbe(packetConn, upstream, nil, target, group, sourceIndex)
	}

	for _, downstream := range downstreams {
		cfg, ok := s.downstreamConfigs[downstream.Name]
		if !ok || cfg.Passive {
			continue
		}

		s.sendProbe(packetConn, downstream, &cfg, target, group, sourceIndex)
	}
}

func (s *Service) sendProbe(
	packetConn *ipv6.PacketConn,
	ifc *net.Interface,
	cfg *config.InterfaceConfig,
	target net.IP,
	group net.IP,
	sourceIndex int,
) {
	if ifc == nil || ifc.Index == sourceIndex || target == nil {
		return
	}

	var (
		src net.IP
		err error
	)

	if cfg == nil {
		src, err = s.resolveUpstreamLinkLocal(ifc)
	} else {
		src, err = s.resolveDownstreamLinkLocal(ifc, *cfg)
	}

	if err != nil || src == nil {
		return
	}

	payload := buildNeighborSolicitationProbe(target, ifc.HardwareAddr)
	if payload == nil {
		return
	}

	controlMessage := &ipv6.ControlMessage{
		IfIndex:  ifc.Index,
		HopLimit: multicastHopLimit,
		Src:      append([]byte(nil), src...),
	}

	_, err = packetConn.WriteTo(payload, controlMessage, &net.IPAddr{IP: group})
	if err != nil {
		s.log.Debug("failed to send probe", "iface", ifc.Name, "target", target, "err", err)
	}
}

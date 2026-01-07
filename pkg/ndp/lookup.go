package ndp

import (
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/jkoelker/ipv6relayd/pkg/config"
)

func (s *Service) lookupTargetInterface(target net.IP) (*net.Interface, bool) {
	addr, ok := netipAddrFromIP(target)
	if !ok {
		return nil, false
	}

	if ifc, _, ok := s.lookupDynamicTarget(addr); ok {
		return ifc, true
	}

	ifc, _, ok := s.lookupStaticBinding(addr)

	return ifc, ok
}

func (s *Service) lookupTargetHostIP(target net.IP) net.IP {
	if target == nil || s.targetCache == nil {
		return nil
	}

	addr, ok := netipAddrFromIP(target)
	if !ok {
		return nil
	}

	key := addr.String()
	if _, expired := s.targetCache.refresh(addr, time.Now()); expired {
		s.removeExpiredHostRoutes([]string{key})

		return nil
	}

	return s.targetCache.hostHint(target)
}

func (s *Service) lookupDynamicTarget(addr netip.Addr) (*net.Interface, config.InterfaceConfig, bool) {
	if s.targetCache == nil {
		return nil, config.InterfaceConfig{}, false
	}

	ifName, expired := s.targetCache.refresh(addr, time.Now())
	if expired {
		s.removeExpiredHostRoutes([]string{addr.String()})
	}

	if ifName == "" {
		return nil, config.InterfaceConfig{}, false
	}

	ifc, cfg, ok := s.lookupInterfaceByName(ifName)
	if !ok {
		return nil, config.InterfaceConfig{}, false
	}

	s.ensureHostRoute(netipAddrToIP(addr), ifc)

	return ifc, cfg, true
}

func (s *Service) lookupStaticBinding(addr netip.Addr) (*net.Interface, config.InterfaceConfig, bool) {
	for _, binding := range s.staticBindings {
		if !binding.prefix.Contains(addr) {
			continue
		}

		ifc, cfg, ok := s.lookupInterfaceByName(binding.iface)
		if !ok {
			continue
		}

		s.ensureHostRoute(netipAddrToIP(addr), ifc)

		return ifc, cfg, true
	}

	return nil, config.InterfaceConfig{}, false
}

func (s *Service) lookupInterfaceByName(name string) (*net.Interface, config.InterfaceConfig, bool) {
	if strings.TrimSpace(name) == "" {
		return nil, config.InterfaceConfig{}, false
	}

	ifc, err := s.ifaces.ByName(name)
	if err != nil {
		return nil, config.InterfaceConfig{}, false
	}

	cfg := s.downstreamConfigs[name]

	return ifc, cfg, true
}

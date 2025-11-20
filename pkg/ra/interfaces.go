package ra

import (
	"net"

	"github.com/jkoelker/ipv6relayd/pkg/config"
)

func (s *Service) downstreamInterfaceByIndex(index int) (*net.Interface, config.InterfaceConfig, bool) {
	for _, downstreamCfg := range s.downstreams {
		ifc, err := s.ifaces.ByName(downstreamCfg.IfName)
		if err != nil {
			continue
		}

		if ifc.Index == index {
			return ifc, downstreamCfg, true
		}
	}

	return nil, config.InterfaceConfig{}, false
}

func interfaceNames(ifcs []*net.Interface) []string {
	names := make([]string, 0, len(ifcs))
	for _, ifc := range ifcs {
		names = append(names, ifc.Name)
	}

	return names
}

package ra

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/net/ipv6"
)

func (s *Service) refreshMulticast(packetConn *ipv6.PacketConn) error {
	upstreamIfc, err := s.ifaces.ByName(s.upstream.IfName)
	if err != nil {
		return fmt.Errorf("lookup upstream interface: %w", err)
	}

	if err := joinGroups(packetConn, upstreamIfc, []string{allNodesMulticast, allRoutersMulticast}); err != nil {
		return fmt.Errorf("rejoin upstream multicast: %w", err)
	}

	var firstErr error

	for _, downstreamCfg := range s.downstreams {
		ifc, err := s.ifaces.ByName(downstreamCfg.IfName)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("lookup downstream %s: %w", downstreamCfg.IfName, err)
			}

			continue
		}

		if err := joinGroups(packetConn, ifc, []string{allNodesMulticast, allRoutersMulticast}); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("rejoin downstream %s multicast: %w", ifc.Name, err)
			}
		}
	}

	return firstErr
}

func joinGroups(packetConn *ipv6.PacketConn, ifc *net.Interface, groups []string) error {
	for _, group := range groups {
		parsedIP := net.ParseIP(group)
		if parsedIP == nil {
			return fmt.Errorf("%w: %s", ErrInvalidMulticastGroup, group)
		}

		if err := packetConn.LeaveGroup(ifc, &net.UDPAddr{IP: parsedIP}); err != nil {
			var opErr *net.OpError
			if errors.As(err, &opErr) {
				var errno syscall.Errno
				if errors.As(opErr.Err, &errno) && (errno == syscall.EADDRNOTAVAIL || errno == syscall.ENODEV) {
					continue
				}
			}
		}

		if err := packetConn.JoinGroup(ifc, &net.UDPAddr{IP: parsedIP}); err != nil {
			return fmt.Errorf("join %s on %s: %w", group, ifc.Name, err)
		}
	}

	return nil
}

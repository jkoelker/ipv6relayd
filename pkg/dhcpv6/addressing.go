package dhcpv6

import (
	"errors"
	"fmt"
	"net"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/netstate"
	"github.com/jkoelker/ipv6relayd/pkg/netutil"
)

// AddressHints returns a copy of the stored hints for the given interface name.
func (s *Service) AddressHints(name string) []net.IP {
	if s.hints == nil {
		return nil
	}

	return s.hints.Hints(name)
}

// BootstrapAddressHints populates missing entries by querying the interface list.
func (s *Service) BootstrapAddressHints() {
	if s.hints == nil {
		return
	}

	s.hints.Bootstrap(s.upstreamIface, s.downstreams)
}

// SelectLinkAddress returns the best source address for the provided interface.
func (s *Service) SelectLinkAddress(downstream *net.Interface, cfg config.InterfaceConfig, _ *net.Interface) net.IP {
	if cfg.IfName != "" {
		if s.linkLocals != nil {
			if ip := s.linkLocals.Downstream(cfg.IfName); ip != nil {
				return ip
			}
		}

		if ip := s.firstHint(cfg.IfName); ip != nil {
			return ip
		}
	}

	if ip := pickPreferredAddress(s.collectInterfaceIPs(downstream)); ip != nil {
		return ip
	}

	return nil
}

func wrapDHCPLinkLocalError(err error) error {
	var parseErr *netstate.ParseError
	if errors.As(err, &parseErr) {
		switch parseErr.Kind {
		case netstate.ParseErrorUpstream:
			return fmt.Errorf("%w: %q", ErrUpstreamLinkLocalParse, parseErr.Value)
		case netstate.ParseErrorDownstream:
			return fmt.Errorf("%w: downstream %s value %q", ErrDownstreamLinkLocalParse, parseErr.IfName, parseErr.Value)
		}
	}

	return err
}

func (s *Service) firstHint(name string) net.IP {
	if s.hints == nil {
		return nil
	}

	if hints := s.hints.Hints(name); len(hints) > 0 {
		return pickPreferredAddress(hints)
	}

	return nil
}

func (s *Service) collectInterfaceIPs(ifc *net.Interface) []net.IP {
	if s.hints == nil {
		return nil
	}

	return s.hints.DiscoverInterface(ifc)
}

func isUsableLinkAddress(candidateIP net.IP) bool {
	return candidateIP != nil &&
		candidateIP.To4() == nil &&
		candidateIP.To16() != nil &&
		!candidateIP.IsUnspecified()
}

func pickPreferredAddress(candidates []net.IP) net.IP {
	var linkLocalFallback net.IP
	for _, candidate := range candidates {
		if candidate == nil || candidate.IsUnspecified() {
			continue
		}

		// Prefer global/ULA per RFC 8415 link-address guidance.
		if !candidate.IsLinkLocalUnicast() {
			return netutil.CloneAddr(candidate)
		}

		if linkLocalFallback == nil {
			linkLocalFallback = netutil.CloneAddr(candidate)
		}
	}

	return linkLocalFallback
}

package ra

import (
	"errors"
	"fmt"
	"net"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/netstate"
)

func (s *Service) resolveLinkLocal(ifc *net.Interface, cfg config.InterfaceConfig) (net.IP, error) {
	if cfg.IfName == s.upstream.IfName {
		return s.resolveUpstreamLinkLocal(ifc)
	}

	ip, err := s.linkLocals.ResolveDownstream(ifc, cfg.IfName)
	if err != nil {
		return nil, wrapRALinkLocalError(err)
	}

	return ip, nil
}

func (s *Service) resolveUpstreamLinkLocal(ifc *net.Interface) (net.IP, error) {
	ip, err := s.linkLocals.ResolveUpstream(ifc)
	if err != nil {
		return nil, wrapRALinkLocalError(err)
	}

	return ip, nil
}

func wrapRALinkLocalError(err error) error {
	var parseErr *netstate.ParseError
	if errors.As(err, &parseErr) {
		switch parseErr.Kind {
		case netstate.ParseErrorUpstream:
			return fmt.Errorf("%w: %s", ErrUpstreamLinkLocalParse, parseErr.Value)
		case netstate.ParseErrorDownstream:
			return fmt.Errorf("%w: %s (%s)", ErrDownstreamLinkLocalParse, parseErr.IfName, parseErr.Value)
		}
	}

	return err
}

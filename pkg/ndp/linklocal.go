package ndp

import (
	"errors"
	"fmt"
	"net"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/netstate"
)

func (s *Service) resolveUpstreamLinkLocal(ifc *net.Interface) (net.IP, error) {
	ip, err := s.linkLocals.ResolveUpstream(ifc)
	if err != nil {
		return nil, wrapNDPLinkLocalError(err)
	}

	return ip, nil
}

func (s *Service) resolveDownstreamLinkLocal(ifc *net.Interface, cfg config.InterfaceConfig) (net.IP, error) {
	ip, err := s.linkLocals.ResolveDownstream(ifc, cfg.IfName)
	if err != nil {
		return nil, wrapNDPLinkLocalError(err)
	}

	return ip, nil
}

func wrapNDPLinkLocalError(err error) error {
	var parseErr *netstate.ParseError
	if errors.As(err, &parseErr) {
		switch parseErr.Kind {
		case netstate.ParseErrorUpstream:
			return fmt.Errorf("upstream link-local %q: %w", parseErr.Value, ErrUpstreamLinkLocalInvalid)
		case netstate.ParseErrorDownstream:
			return fmt.Errorf("downstream %s link-local %q: %w", parseErr.IfName, parseErr.Value, ErrDownstreamLinkLocalInvalid)
		}
	}

	return err
}

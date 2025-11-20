package ra

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/netutil"
)

func (s *Service) forwardToDownstreams(
	ctx context.Context,
	packetConn *ipv6.PacketConn,
	msg *ndp.RouterAdvertisement,
) error {
	var firstErr error

	for _, downstreamCfg := range s.downstreams {
		_, err := s.forwardRouterAdvertisementToDownstream(packetConn, msg, downstreamCfg)

		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}

		if err := ctx.Err(); err != nil {
			return fmt.Errorf("context canceled while forwarding RA: %w", err)
		}
	}

	return firstErr
}

func (s *Service) forwardRouterAdvertisementToDownstream(
	packetConn *ipv6.PacketConn,
	msg *ndp.RouterAdvertisement,
	downstreamCfg config.InterfaceConfig,
) (bool, error) {
	if downstreamCfg.Passive {
		return false, nil
	}

	downstream, err := s.ifaces.ByName(downstreamCfg.IfName)
	if err != nil {
		s.log.Warn("failed to resolve downstream during RA forwarding", "iface", downstreamCfg.IfName, "err", err)

		return false, fmt.Errorf("resolve downstream %s: %w", downstreamCfg.IfName, err)
	}

	clone := cloneRouterAdvertisement(msg)
	modifiedPayload, err := s.prepareRouterAdvertisement(clone, downstream)
	if err != nil {
		s.log.Warn("failed to prepare router advertisement for downstream", "iface", downstream.Name, "err", err)

		return false, nil
	}

	linkLocal, err := s.resolveLinkLocal(downstream, downstreamCfg)
	if err != nil {
		s.log.Warn("no link-local source on downstream; skipping RA send", "iface", downstream.Name, "err", err)

		return false, nil
	}

	src := linkLocal.To16()
	if src == nil {
		s.log.Warn("link-local address not IPv6; skipping RA send", "iface", downstream.Name)

		return false, nil
	}

	if err := packetConn.SetMulticastInterface(downstream); err != nil {
		s.log.Warn("failed to select multicast interface", "iface", downstream.Name, "err", err)

		return false, nil
	}

	dst := &net.IPAddr{IP: s.allNodesIP, Zone: downstream.Name}
	controlMsg := &ipv6.ControlMessage{
		IfIndex:  downstream.Index,
		HopLimit: multicastHopLimit,
		Src:      append([]byte(nil), src...),
	}

	if err := s.writePacket(packetConn, modifiedPayload, controlMsg, dst, downstream, "RA"); err != nil {
		s.log.Warn("failed to forward RA downstream", "iface", downstream.Name, "err", err)

		return false, err
	}

	s.log.Debug("forwarded RA downstream", "iface", downstream.Name, "bytes", len(modifiedPayload))

	return true, nil
}

func (s *Service) writePacket(
	packetConn *ipv6.PacketConn,
	payload []byte,
	controlMsg *ipv6.ControlMessage,
	dst *net.IPAddr,
	ifc *net.Interface,
	packetDesc string,
) error {
	if _, err := packetConn.WriteTo(payload, controlMsg, dst); err != nil {
		if errors.Is(err, syscall.EINVAL) {
			controlMsg.Src = nil
			if _, retryErr := packetConn.WriteTo(payload, controlMsg, dst); retryErr == nil {
				s.log.Debug("retry "+packetDesc+" send without explicit source", "iface", ifc.Name)

				return nil
			}
		}

		if netutil.IsNoDeviceError(err) {
			s.ifaces.Flush()
		}

		return fmt.Errorf("write %s on %s: %w", packetDesc, ifc.Name, err)
	}

	return nil
}

func (s *Service) storeLastRA(msg *ndp.RouterAdvertisement) {
	s.lastRAMu.Lock()
	defer s.lastRAMu.Unlock()

	clone := *msg
	clone.Options = append([]ndp.Option(nil), msg.Options...)
	pruneZeroLifetimeOptions(&clone)

	maxLifetime := maxRALifetime(&clone)
	if maxLifetime <= 0 {
		s.clearLastRALocked()

		return
	}

	buf, err := ndp.MarshalMessage(&clone)
	if err != nil {
		s.log.Warn("failed to cache RA", "err", err)
		s.clearLastRALocked()

		return
	}

	s.lastRA = append([]byte(nil), buf...)
	now := time.Now()
	s.lastRAReceived = now
	s.lastRAExpiry = now.Add(maxLifetime)
}

func (s *Service) loadLastRA() []byte {
	s.lastRAMu.Lock()
	defer s.lastRAMu.Unlock()

	if len(s.lastRA) == 0 {
		return nil
	}

	now := time.Now()
	if !s.lastRAExpiry.IsZero() && now.After(s.lastRAExpiry) {
		s.clearLastRALocked()

		return nil
	}

	buf := make([]byte, len(s.lastRA))
	copy(buf, s.lastRA)

	elapsed := time.Duration(0)
	if !s.lastRAReceived.IsZero() {
		elapsed = now.Sub(s.lastRAReceived)
	}

	hasRemaining, err := clampRALifetimes(buf, elapsed)
	if err != nil {
		s.log.Warn("failed to clamp cached RA lifetimes; dropping cache", "err", err)
		s.clearLastRALocked()

		return nil
	}

	if !hasRemaining {
		s.clearLastRALocked()

		return nil
	}

	return buf
}

func (s *Service) clearLastRALocked() {
	s.lastRA = nil
	s.lastRAReceived = time.Time{}
	s.lastRAExpiry = time.Time{}
}

func (s *Service) forwardRouterSolicitation(
	ctx context.Context,
	packetConn *ipv6.PacketConn,
	upstream *net.Interface,
	payload []byte,
) error {
	dst := &net.IPAddr{IP: s.allRoutersIP, Zone: upstream.Name}

	linkLocal, err := s.resolveUpstreamLinkLocal(upstream)
	if err != nil {
		return fmt.Errorf("missing link-local on upstream %s: %w", upstream.Name, err)
	}

	src := linkLocal.To16()
	if src == nil {
		return fmt.Errorf("%w: %s", ErrUpstreamLinkLocalIPv6, upstream.Name)
	}

	prepared, err := s.prepareRouterSolicitation(payload, upstream)
	if err != nil {
		return fmt.Errorf("prepare router solicitation: %w", err)
	}

	controlMsg := &ipv6.ControlMessage{
		IfIndex:  upstream.Index,
		HopLimit: multicastHopLimit,
		Src:      append([]byte(nil), src...),
	}
	if err := s.writePacket(packetConn, prepared, controlMsg, dst, upstream, "RS"); err != nil {
		return err
	}

	s.log.Debug("forwarded RS upstream", "iface", upstream.Name, "bytes", len(prepared))

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context canceled while forwarding RS: %w", err)
	}

	return nil
}

func (s *Service) prepareRouterAdvertisement(msg *ndp.RouterAdvertisement, downstream *net.Interface) ([]byte, error) {
	rewriter := newRouterAdvertisementRewriter(s, downstream)

	if err := rewriter.Rewrite(msg); err != nil {
		return nil, err
	}

	encoded, err := ndp.MarshalMessage(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal router advertisement: %w", err)
	}

	return encoded, nil
}

func (s *Service) prepareRouterSolicitation(payload []byte, upstream *net.Interface) ([]byte, error) {
	msg, err := parseRouterSolicitationPayload(payload)
	if err != nil {
		return nil, err
	}

	rewriter := newRouterSolicitationRewriter(s, upstream)
	if err := rewriter.Rewrite(msg); err != nil {
		return nil, err
	}

	encoded, err := ndp.MarshalMessage(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal router solicitation: %w", err)
	}

	return encoded, nil
}

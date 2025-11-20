package dhcpv6

import (
	"context"
	"fmt"
	"net"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"golang.org/x/net/ipv6"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/netutil"
)

func (s *Service) handleDownstream(
	ctx context.Context,
	pktConn *ipv6.PacketConn,
	downstreamIface *net.Interface,
	downstreamCfg config.InterfaceConfig,
	src net.Addr,
	payload []byte,
) error {
	frame, err := dhcpv6.FromBytes(payload)
	if err != nil {
		return fmt.Errorf("parse dhcpv6: %w", err)
	}

	if s.shouldDropDueToHopCount(frame, downstreamIface.Name) {
		return nil
	}

	peerAddr, err := peerAddrFrom(src)
	if err != nil {
		return fmt.Errorf("determine peer addr: %w", err)
	}

	upstreamIface, err := s.ifaces.ByName(s.upstreamIface.IfName)
	if err != nil {
		return fmt.Errorf("lookup upstream interface %s: %w", s.upstreamIface.IfName, err)
	}

	linkAddr, err := s.LinkAddressForRelay(downstreamIface, downstreamCfg, upstreamIface, peerAddr, frame)
	if err != nil {
		return fmt.Errorf("select link address: %w", err)
	}

	relay, err := s.BuildRelayForward(frame, linkAddr, peerAddr, downstreamIface)
	if err != nil {
		return fmt.Errorf("build relay-forward: %w", err)
	}

	s.recordTransactionFromFrame(frame, downstreamIface.Name)

	return s.forwardRelay(ctx, pktConn, upstreamIface, relay, frame, downstreamIface.Name)
}

func (s *Service) handleUpstream(ctx context.Context, pktConn *ipv6.PacketConn, payload []byte) error {
	relay, drop, err := s.parseUpstreamRelay(payload)
	if err != nil {
		return err
	}
	if drop {
		return nil
	}

	inner := relay.Options.RelayMessage()
	if inner == nil {
		return ErrMissingRelayMessageOpt
	}

	raw, msgType, dstPort, err := s.PrepareDownstreamPayload(inner)
	if err != nil {
		return err
	}

	xid, err := dhcpv6.GetTransactionID(inner)
	if err != nil {
		return fmt.Errorf("extract transaction id: %w", err)
	}

	transactionID := transactionIDToUint(xid)
	ifaceName, err := s.resolveDownstreamInterface(relay, transactionID)
	if err != nil {
		return err
	}

	if s.transactions != nil {
		s.transactions.remove(transactionID)
	}

	dstIface, err := s.ifaces.ByName(ifaceName)
	if err != nil {
		return fmt.Errorf("lookup downstream interface %s: %w", ifaceName, err)
	}

	dstAddr, err := s.sendDownstreamReply(ctx, pktConn, dstIface, dstPort, raw, relay)
	if err != nil {
		return err
	}

	s.log.Debug(
		"forwarded dhcpv6 reply downstream",
		"iface", dstIface.Name,
		"peer", dstAddr,
		"msg_type", msgType,
	)

	return nil
}

func (s *Service) parseUpstreamRelay(payload []byte) (*dhcpv6.RelayMessage, bool, error) {
	frame, err := dhcpv6.FromBytes(payload)
	if err != nil {
		return nil, false, fmt.Errorf("parse upstream payload: %w", err)
	}

	relay, ok := frame.(*dhcpv6.RelayMessage)
	if !ok {
		s.log.Debug("drop non-relay upstream packet", "type", frame.Type().String())

		return nil, true, nil
	}

	if relay.MessageType != dhcpv6.MessageTypeRelayReply {
		s.log.Debug("drop non-reply relay message", "type", relay.MessageType)

		return nil, true, nil
	}

	return relay, false, nil
}

func (s *Service) PrepareDownstreamPayload(inner dhcpv6.DHCPv6) ([]byte, string, int, error) {
	switch payload := inner.(type) {
	case *dhcpv6.Message:
		// Forward replies unchanged per RFC 8415 §19.2; only apply
		// optional DNS/DNSSL overrides when allowed.
		s.RewriteReplyOptions(payload)
		msgType := payload.Type().String()

		return payload.ToBytes(), msgType, clientPort, nil
	case *dhcpv6.RelayMessage:
		return payload.ToBytes(), payload.MessageType.String(), serverPort, nil
	default:
		return nil, "", 0, fmt.Errorf("%w: %T", ErrUnexpectedRelayPayload, inner)
	}
}

func (s *Service) resolveDownstreamInterface(relay *dhcpv6.RelayMessage, txnID uint32) (string, error) {
	if name, ok := s.lookupInterfaceID(relay); ok {
		return name, nil
	}

	if name, ok := s.lookupInterfaceByTransaction(txnID); ok {
		return name, nil
	}

	if name, ok := s.interfaceNameByLinkAddr(relay.LinkAddr); ok {
		return name, nil
	}

	return "", ErrDownstreamInterface
}

func (s *Service) sendDownstreamReply(
	ctx context.Context,
	pktConn *ipv6.PacketConn,
	dstIface *net.Interface,
	dstPort int,
	raw []byte,
	relay *dhcpv6.RelayMessage,
) (string, error) {
	dstAddr, err := downstreamDestination(relay, dstPort)
	if err != nil {
		return "", err
	}

	cm := downstreamControlMessage(dstIface, dstAddr)

	if _, err := pktConn.WriteTo(raw, cm, dstAddr); err != nil {
		if netutil.IsNoDeviceError(err) {
			s.ifaces.Flush()
			if refreshErr := s.refreshMulticast(pktConn); refreshErr != nil {
				s.log.Warn("failed to refresh multicast after downstream send error", "err", refreshErr)
			}
		}

		return "", fmt.Errorf("write downstream: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("context canceled after downstream write: %w", err)
	}

	return dstAddr.String(), nil
}

func downstreamDestination(relay *dhcpv6.RelayMessage, dstPort int) (*net.UDPAddr, error) {
	if relay == nil || relay.PeerAddr == nil || relay.PeerAddr.IsUnspecified() {
		return nil, ErrMissingPeerAddress
	}

	return &net.UDPAddr{
		IP:   relay.PeerAddr,
		Port: dstPort,
	}, nil
}

func downstreamControlMessage(dstIface *net.Interface, dstAddr *net.UDPAddr) *ipv6.ControlMessage {
	return &ipv6.ControlMessage{
		IfIndex:  dstIface.Index,
		HopLimit: HopLimitForDestination(dstAddr),
	}
}

func (s *Service) downstreamInterfaceByIndex(index int) (*net.Interface, config.InterfaceConfig, error) {
	for _, downstream := range s.downstreams {
		ifc, err := s.ifaces.ByName(downstream.IfName)
		if err != nil {
			continue
		}

		if ifc.Index == index {
			return ifc, downstream, nil
		}
	}

	return nil, config.InterfaceConfig{}, ErrInterfaceNotManaged
}

func (s *Service) lookupInterfaceID(relay *dhcpv6.RelayMessage) (string, bool) {
	ifaceID := relay.Options.InterfaceID()
	if len(ifaceID) == 0 {
		return "", false
	}

	return string(ifaceID), true
}

func (s *Service) interfaceNameByLinkAddr(addr net.IP) (string, bool) {
	if len(addr) == 0 || addr.IsUnspecified() {
		return "", false
	}

	needle := addr.To16()
	if needle == nil {
		return "", false
	}

	for _, downstream := range s.downstreams {
		ifc, err := s.ifaces.ByName(downstream.IfName)
		if err != nil {
			continue
		}

		candidate := s.SelectLinkAddress(ifc, downstream, nil)
		if candidate == nil {
			continue
		}

		if candidate.Equal(needle) {
			return downstream.IfName, true
		}
	}

	return "", false
}

func peerAddrFrom(addr net.Addr) (net.IP, error) {
	udp, ok := addr.(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("%w: %T", ErrUnexpectedAddrType, addr)
	}

	return udp.IP, nil
}

// LinkAddressForRelay returns the link-address to use when forwarding a frame.
func (s *Service) LinkAddressForRelay(
	downstreamIface *net.Interface,
	downstreamCfg config.InterfaceConfig,
	upstreamIface *net.Interface,
	peerAddr net.IP,
	frame dhcpv6.DHCPv6,
) (net.IP, error) {
	selectedAddr := s.SelectLinkAddress(downstreamIface, downstreamCfg, upstreamIface)

	if _, ok := frame.(*dhcpv6.RelayMessage); ok {
		// RFC 8415 §19.1.2: when relaying a Relay-forward and the source address
		// is global/ULA, set link-address to ::. Otherwise, prefer a qualified
		// address from the incoming link, falling back to :: when unavailable.
		if peerAddr != nil && peerAddr.IsGlobalUnicast() {
			return netutil.CloneAddr(net.IPv6zero), nil
		}

		if selectedAddr == nil || selectedAddr.IsUnspecified() {
			return netutil.CloneAddr(net.IPv6zero), nil
		}

		return netutil.CloneAddr(selectedAddr), nil
	}

	// RFC 8415 §19.1.1: client messages should carry a GUA/ULA for the link when
	// available, even when Interface-ID is present. Preserve the selected address
	// (which already prefers global/ULA), falling back to :: only when none is
	// discoverable.
	if selectedAddr == nil || selectedAddr.IsUnspecified() {
		return netutil.CloneAddr(net.IPv6zero), nil
	}

	return netutil.CloneAddr(selectedAddr), nil
}

func (s *Service) BuildRelayForward(
	frame dhcpv6.DHCPv6,
	linkAddr net.IP,
	peerAddr net.IP,
	downstreamIface *net.Interface,
) (*dhcpv6.RelayMessage, error) {
	relay, err := dhcpv6.EncapsulateRelay(frame, dhcpv6.MessageTypeRelayForward, linkAddr, peerAddr)
	if err != nil {
		return nil, fmt.Errorf("encapsulate relay-forward: %w", err)
	}

	// RFC 8415 §20.1.1: if we receive a Relay-Forward, increment hop-count before forwarding.
	if inner, ok := frame.(*dhcpv6.RelayMessage); ok {
		relay.HopCount = inner.HopCount + 1
	}

	s.decorateRelayForward(relay, downstreamIface, peerAddr, frame)

	addInterfaceID := s.cfg.InterfaceIDEnabled()
	if requiresInterfaceID(linkAddr) {
		// RFC 8415 §19.1.1/§19.1.2: include Interface-ID when link-address
		// alone cannot identify the incoming link (including link-local or
		// unspecified addresses), regardless of user preference.
		addInterfaceID = true
	}

	if addInterfaceID {
		relay.Options.Add(dhcpv6.OptInterfaceID([]byte(downstreamIface.Name)))
	}

	return relay, nil
}

func (s *Service) recordTransactionFromFrame(frame dhcpv6.DHCPv6, ifaceName string) {
	if xid, err := dhcpv6.GetTransactionID(frame); err == nil {
		s.StoreTransaction(transactionIDToUint(xid), ifaceName)
	}
}

func requiresInterfaceID(linkAddr net.IP) bool {
	if linkAddr == nil || linkAddr.IsUnspecified() {
		return true
	}

	return !linkAddr.IsGlobalUnicast()
}

func (s *Service) forwardRelay(
	ctx context.Context,
	pktConn *ipv6.PacketConn,
	upstreamIface *net.Interface,
	relay *dhcpv6.RelayMessage,
	frame dhcpv6.DHCPv6,
	downstreamName string,
) error {
	raw := relay.ToBytes()
	upstream := s.currentUpstream()
	if upstream == nil {
		return ErrUpstreamNotConfigured
	}

	controlMessage := &ipv6.ControlMessage{
		IfIndex:  upstreamIface.Index,
		HopLimit: HopLimitForDestination(upstream),
	}

	if _, err := pktConn.WriteTo(raw, controlMessage, upstream); err != nil {
		if netutil.IsNoDeviceError(err) {
			s.ifaces.Flush()
			if refreshErr := s.refreshMulticast(pktConn); refreshErr != nil {
				s.log.Warn("failed to refresh multicast after upstream send error", "err", refreshErr)
			}
		}

		return fmt.Errorf("write upstream: %w", err)
	}

	s.log.Debug("forwarded dhcpv6 message upstream", "iface", downstreamName, "msg_type", dhcpv6MessageType(frame))

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context canceled after upstream forward: %w", err)
	}

	return nil
}

func dhcpv6MessageType(frame dhcpv6.DHCPv6) string {
	if msg, ok := frame.(*dhcpv6.Message); ok {
		return msg.Type().String()
	}

	return "relay"
}

// HopLimitForDestination returns the hop limit appropriate for the destination.
// Exported for tests and potential reuse.
func HopLimitForDestination(dst *net.UDPAddr) int {
	if dst == nil || dst.IP == nil {
		return defaultHopLimit
	}

	if dst.IP.IsMulticast() {
		// RFC 8415 §19 mandates hop-limit of 8 for any multicast relay traffic.
		return multicastRelayHopLimit
	}

	return defaultHopLimit
}

func (s *Service) shouldDropDueToHopCount(frame dhcpv6.DHCPv6, ifaceName string) bool {
	relay, ok := frame.(*dhcpv6.RelayMessage)
	if !ok {
		return false
	}

	if relay.HopCount < MaxHopCount {
		return false
	}

	s.log.Warn(
		"dropping dhcpv6 relay-forward with excessive hop-count",
		"hop_count", relay.HopCount,
		"iface", ifaceName,
	)

	return true
}

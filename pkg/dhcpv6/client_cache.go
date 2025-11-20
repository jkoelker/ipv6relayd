package dhcpv6

import (
	"fmt"
	"net"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/vishvananda/netlink"

	"github.com/jkoelker/ipv6relayd/pkg/cache"
	"github.com/jkoelker/ipv6relayd/pkg/netutil"
)

type clientHWEntry struct {
	hw     net.HardwareAddr
	hwType iana.HWType
}

type clientCache struct {
	store *cache.TTL[string, clientHWEntry]
}

func newClientCache(ttl time.Duration) *clientCache {
	store := cache.NewTTL[string, clientHWEntry](ttl)
	if store == nil {
		return nil
	}

	return &clientCache{
		store: store,
	}
}

func (c *clientCache) lookup(key string) (iana.HWType, net.HardwareAddr, bool) {
	if key == "" || c == nil || c.store == nil {
		return 0, nil, false
	}

	entry, ok, _ := c.store.Get(key)
	if !ok {
		return 0, nil, false
	}

	return entry.hwType, netutil.CloneAddr(entry.hw), true
}

func (c *clientCache) remember(key string, hwType iana.HWType, hwAddr net.HardwareAddr) {
	if key == "" || len(hwAddr) == 0 || c == nil || c.store == nil {
		return
	}

	c.store.Add(key, clientHWEntry{
		hw:     netutil.CloneAddr(hwAddr),
		hwType: hwType,
	})
}

func (s *Service) decorateRelayForward(
	relay *dhcpv6.RelayMessage,
	downstreamIface *net.Interface,
	peerIP net.IP,
	inner dhcpv6.DHCPv6,
) {
	if relay == nil || downstreamIface == nil {
		return
	}

	s.maybeAddRemoteID(relay, downstreamIface)

	msg, ok := inner.(*dhcpv6.Message)
	if !ok {
		return
	}

	s.maybeAddClientLinkLayer(relay, downstreamIface, peerIP, msg)
}

func (s *Service) maybeAddRemoteID(relay *dhcpv6.RelayMessage, downstreamIface *net.Interface) {
	if relay == nil || downstreamIface == nil {
		return
	}

	enterprise := s.remoteIDEnterprise()
	if enterprise == 0 && !s.cfg.RemoteID.Disabled && s.log != nil {
		s.remoteIDLogOnce.Do(func() {
			s.log.Info(
				"skip remote-id option; enterprise_id not configured",
				"hint", "set dhcpv6.remote_id.enterprise_id to enable Remote-ID",
			)
		})
	}

	if payload := GenerateRemoteIDPayload(s.cfg.RemoteID, downstreamIface); len(payload) > 0 &&
		enterprise != 0 && !s.cfg.RemoteID.Disabled {
		relay.Options.Add(&dhcpv6.OptRemoteID{
			EnterpriseNumber: enterprise,
			RemoteID:         payload,
		})
	}
}

func (s *Service) maybeAddClientLinkLayer(
	relay *dhcpv6.RelayMessage,
	downstreamIface *net.Interface,
	peerIP net.IP,
	msg *dhcpv6.Message,
) {
	if relay == nil || downstreamIface == nil || msg == nil {
		return
	}
	if peerIP == nil || !peerIP.IsLinkLocalUnicast() {
		return
	}

	if len(relay.Options.Get(dhcpv6.OptionClientLinkLayerAddr)) > 0 {
		return
	}

	if hwType, hwAddr, ok := s.lookupClientHardware(downstreamIface, peerIP, msg); ok && len(hwAddr) > 0 {
		relay.Options.Add(dhcpv6.OptClientLinkLayerAddress(hwType, hwAddr))
	}
}

func (s *Service) lookupClientHardware(
	downstreamIface *net.Interface,
	peerIP net.IP,
	inner dhcpv6.DHCPv6,
) (iana.HWType, net.HardwareAddr, bool) {
	if downstreamIface == nil {
		return 0, nil, false
	}

	key := cacheKey(downstreamIface, peerIP)
	if hwType, hwAddr, ok := s.clientCache.lookup(key); ok {
		return hwType, hwAddr, true
	}

	if hwType, hwAddr, ok := s.neighborClientHardware(key, downstreamIface, peerIP); ok {
		return hwType, hwAddr, true
	}

	return s.clientHardwareFromMessage(key, inner)
}

func (s *Service) neighborClientHardware(
	key string,
	downstreamIface *net.Interface,
	peerIP net.IP,
) (iana.HWType, net.HardwareAddr, bool) {
	hwAddr, err := neighborHardware(downstreamIface, peerIP)
	switch {
	case err != nil:
		s.log.Debug(
			"failed to query neighbor table for client link-layer address",
			"iface", downstreamIface.Name,
			"ip", peerIP,
			"err", err,
		)

		return 0, nil, false
	case len(hwAddr) == 0:
		return 0, nil, false
	default:
		if key != "" {
			s.clientCache.remember(key, iana.HWTypeEthernet, hwAddr)
		}

		return iana.HWTypeEthernet, hwAddr, true
	}
}

func (s *Service) clientHardwareFromMessage(key string, inner dhcpv6.DHCPv6) (iana.HWType, net.HardwareAddr, bool) {
	msg, ok := inner.(*dhcpv6.Message)
	if !ok {
		return 0, nil, false
	}

	hwType, hwAddr, ok := HardwareFromDUID(msg.Options.ClientID())
	if !ok || len(hwAddr) == 0 {
		return 0, nil, false
	}

	if key != "" {
		s.clientCache.remember(key, hwType, hwAddr)
	}

	return hwType, hwAddr, true
}

// HardwareFromDUID returns the hardware type/address embedded in the provided DUID.
func HardwareFromDUID(duid dhcpv6.DUID) (iana.HWType, net.HardwareAddr, bool) {
	switch typedDUID := duid.(type) {
	case *dhcpv6.DUIDLL:
		if len(typedDUID.LinkLayerAddr) == 0 {
			return 0, nil, false
		}

		return typedDUID.HWType, netutil.CloneAddr(typedDUID.LinkLayerAddr), true
	case *dhcpv6.DUIDLLT:
		if len(typedDUID.LinkLayerAddr) == 0 {
			return 0, nil, false
		}

		return typedDUID.HWType, netutil.CloneAddr(typedDUID.LinkLayerAddr), true
	default:
		return 0, nil, false
	}
}

func neighborHardware(iface *net.Interface, peerIP net.IP) (net.HardwareAddr, error) {
	if iface == nil || peerIP == nil || len(peerIP) == 0 || peerIP.IsUnspecified() {
		return nil, nil
	}

	neighs, err := netlink.NeighList(iface.Index, netlink.FAMILY_V6)
	if err != nil {
		return nil, fmt.Errorf("list neighbors: %w", err)
	}

	for _, neigh := range neighs {
		if neigh.IP == nil || len(neigh.HardwareAddr) == 0 {
			continue
		}

		if peerIP.Equal(neigh.IP) {
			return netutil.CloneAddr(neigh.HardwareAddr), nil
		}
	}

	return nil, nil
}

func cacheKey(iface *net.Interface, peerIP net.IP) string {
	if iface == nil || peerIP == nil || len(peerIP) == 0 || peerIP.IsUnspecified() {
		return ""
	}

	return iface.Name + "|" + peerIP.String()
}

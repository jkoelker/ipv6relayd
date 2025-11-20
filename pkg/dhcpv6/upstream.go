package dhcpv6

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/iface"
	"github.com/jkoelker/ipv6relayd/pkg/netutil"
)

// RouteListFilteredFunc describes the signature of netlink.RouteListFiltered.
type RouteListFilteredFunc func(int, *netlink.Route, uint64) ([]netlink.Route, error)

func determineDHCPv6Upstream(
	upstreamIface config.InterfaceConfig,
	cfg config.DHCPv6Config,
	ifaces *iface.Manager,
) (*net.UDPAddr, bool, error) {
	if cfg.Upstream == "" {
		addr, err := AutoDiscoverUpstream(upstreamIface, ifaces)
		if err != nil {
			if errors.Is(err, ErrNoIPv6Gateway) {
				return fallbackMulticastUpstream(upstreamIface.IfName), true, nil
			}

			return nil, false, fmt.Errorf("dhcpv6 upstream auto-discovery: %w", err)
		}

		return addr, true, nil
	}

	addr, err := resolveUpstream(cfg.Upstream)
	if err != nil {
		return nil, false, err
	}

	return addr, false, nil
}

func resolveUpstream(value string) (*net.UDPAddr, error) {
	if value == "" {
		return nil, ErrEmptyUpstreamValue
	}

	if addr, err := net.ResolveUDPAddr("udp6", value); err == nil {
		if addr.Port == 0 {
			addr.Port = serverPort
		}

		return addr, nil
	}

	canonical, hasPort := canonicalizeUDPAddr(value)
	if !hasPort {
		canonical = appendDefaultPort(canonical, serverPort)
	}

	addr, err := net.ResolveUDPAddr("udp6", canonical)
	if err != nil {
		return nil, fmt.Errorf("resolve upstream %q: %w", value, err)
	}

	if addr.Port == 0 {
		addr.Port = serverPort
	}

	return addr, nil
}

// AutoDiscoverUpstream inspects the upstream's default route to find a DHCPv6 server.
func AutoDiscoverUpstream(upstream config.InterfaceConfig, ifaces *iface.Manager) (*net.UDPAddr, error) {
	return AutoDiscoverUpstreamWithRoutes(upstream, ifaces, nil)
}

// AutoDiscoverUpstreamWithRoutes mirrors AutoDiscoverUpstream but allows tests to
// inject a custom route listing implementation.
func AutoDiscoverUpstreamWithRoutes(
	upstream config.InterfaceConfig,
	ifaces *iface.Manager,
	routeFn RouteListFilteredFunc,
) (*net.UDPAddr, error) {
	if routeFn == nil {
		routeFn = netlink.RouteListFiltered
	}

	ifc, err := lookupUpstreamInterface(upstream, ifaces)
	if err != nil {
		return nil, err
	}

	routes, err := ipv6DefaultRoutes(ifc, routeFn)
	if err != nil {
		return nil, err
	}

	linkLocal, fallback := pickGatewayCandidates(routes, ifc.Name)
	switch {
	case linkLocal != nil:
		return linkLocal, nil
	case fallback != nil:
		return fallback, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrNoIPv6Gateway, upstream.IfName)
	}
}

func lookupUpstreamInterface(upstream config.InterfaceConfig, ifaces *iface.Manager) (*net.Interface, error) {
	if upstream.IfName == "" {
		return nil, ErrUpstreamInterfaceNeeded
	}

	ifc, err := ifaces.ByName(upstream.IfName)
	if err != nil {
		return nil, fmt.Errorf("lookup upstream interface %q: %w", upstream.IfName, err)
	}

	return ifc, nil
}

func ipv6DefaultRoutes(ifc *net.Interface, routeFn RouteListFilteredFunc) ([]netlink.Route, error) {
	filter := &netlink.Route{LinkIndex: ifc.Index}
	if routeFn == nil {
		routeFn = netlink.RouteListFiltered
	}

	routes, err := routeFn(netlink.FAMILY_V6, filter, netlink.RT_FILTER_OIF)
	if err != nil {
		return nil, fmt.Errorf("list routes on %s: %w", ifc.Name, err)
	}

	return routes, nil
}

func pickGatewayCandidates(routes []netlink.Route, ifName string) (*net.UDPAddr, *net.UDPAddr) {
	var fallback *net.UDPAddr
	for _, route := range routes {
		if !isDefaultIPv6Route(route) || route.Gw == nil {
			continue
		}

		candidate := buildGatewayAddr(route.Gw)
		if candidate == nil {
			continue
		}

		if candidate.IP.IsLinkLocalUnicast() {
			candidate.Zone = ifName

			return candidate, fallback
		}

		if fallback == nil {
			fallback = candidate
		}
	}

	return nil, fallback
}

func buildGatewayAddr(ip net.IP) *net.UDPAddr {
	clone := netutil.CloneAddr(ip)
	if clone == nil || clone.To16() == nil || clone.IsUnspecified() {
		return nil
	}

	return &net.UDPAddr{IP: clone, Port: serverPort}
}

func isDefaultIPv6Route(route netlink.Route) bool {
	if route.Dst == nil {
		return true
	}

	ones, bits := route.Dst.Mask.Size()

	return ones == 0 && bits == 0
}

func canonicalizeUDPAddr(value string) (string, bool) {
	if strings.HasPrefix(value, "[") {
		if _, _, err := net.SplitHostPort(value); err == nil {
			return value, true
		}

		if strings.HasSuffix(value, "]") {
			return value, false
		}

		return value, false
	}

	if strings.Count(value, ":") == 1 {
		if host, port, err := net.SplitHostPort(value); err == nil {
			if port == "" {
				return host, false
			}

			return net.JoinHostPort(host, port), true
		}
	} else if strings.Count(value, ":") == 0 {
		return value, false
	}

	if host, port, ok := splitZoneHostPort(value); ok {
		return fmt.Sprintf("[%s]:%s", host, port), true
	}

	return fmt.Sprintf("[%s]", value), false
}

func appendDefaultPort(addr string, port int) string {
	if strings.HasSuffix(addr, "]") {
		return fmt.Sprintf("%s:%d", addr, port)
	}

	if strings.Contains(addr, ":") {
		return fmt.Sprintf("[%s]:%d", addr, port)
	}

	return net.JoinHostPort(addr, strconv.Itoa(port))
}

func splitZoneHostPort(addr string) (string, string, bool) {
	if !strings.Contains(addr, "%") {
		return "", "", false
	}

	last := strings.LastIndex(addr, ":")
	if last == -1 {
		return "", "", false
	}

	host := addr[:last]
	port := addr[last+1:]
	if port == "" || strings.ContainsAny(port, "[]:") {
		return "", "", false
	}

	if !isAllDigits(port) {
		return "", "", false
	}

	return host, port, true
}

func isAllDigits(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}

	return len(value) > 0
}

func fallbackMulticastUpstream(ifName string) *net.UDPAddr {
	addr := &net.UDPAddr{IP: net.ParseIP(mcastAddr), Port: serverPort}
	if ifName != "" {
		addr.Zone = ifName
	}

	return addr
}

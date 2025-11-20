package ndp

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"syscall"

	"github.com/vishvananda/netlink"
)

// routeManager owns host and static route bookkeeping.
type routeManager struct {
	log *slog.Logger

	hostMu     sync.Mutex
	hostRoutes map[string]*netlink.Route

	staticMu     sync.Mutex
	staticRoutes []*netlink.Route
}

func newRouteManager(log *slog.Logger) *routeManager {
	return &routeManager{
		log:        log,
		hostRoutes: make(map[string]*netlink.Route),
	}
}

func (r *routeManager) ensureHostRoute(target net.IP, iface *net.Interface) {
	key, route := r.newHostRoute(target, iface)

	if route == nil {
		return
	}

	r.logHostRouteAttempt(key, iface)

	if r.existingHostRouteMatches(key, iface) {
		return
	}

	if err := netlink.RouteReplace(route); err != nil {
		r.logHostRouteError("install", key, iface, err)

		return
	}

	r.recordHostRoute(key, route)
	r.logHostRouteInstalled(key, iface)
}

func (r *routeManager) removeHostRoutes(keys []string) {
	if r == nil || len(keys) == 0 {
		return
	}

	r.hostMu.Lock()
	defer r.hostMu.Unlock()

	for _, key := range keys {
		r.removeHostRouteLocked(key)
	}
}

func (r *routeManager) cleanupHostRoutes() {
	if r == nil {
		return
	}

	r.hostMu.Lock()
	defer r.hostMu.Unlock()

	for key := range r.hostRoutes {
		r.removeHostRouteLocked(key)
	}
}

func (r *routeManager) removeHostRouteLocked(key string) {
	route, ok := r.hostRoutes[key]
	if !ok {
		return
	}

	if route != nil {
		if err := netlink.RouteDel(route); err != nil && !isRouteNotFound(err) {
			if r.log != nil {
				r.log.Debug("failed to remove host route", "dst", route.Dst, "err", err)
			}
		}
	}

	delete(r.hostRoutes, key)
}

func (r *routeManager) appendStaticRouteLocked(route *netlink.Route) {
	r.staticRoutes = append(r.staticRoutes, route)
}

func (r *routeManager) cleanupStaticRoutes() {
	if r == nil {
		return
	}

	r.staticMu.Lock()
	defer r.staticMu.Unlock()

	r.cleanupStaticRoutesLocked()
}

func (r *routeManager) cleanupStaticRoutesLocked() {
	for _, route := range r.staticRoutes {
		if route == nil {
			continue
		}

		if err := netlink.RouteDel(route); err != nil && !isRouteNotFound(err) {
			if r.log != nil {
				r.log.Debug("failed to remove static route", "dst", route.Dst, "err", err)
			}
		}
	}

	r.staticRoutes = nil
}

func (r *routeManager) newHostRoute(target net.IP, iface *net.Interface) (string, *netlink.Route) {
	if r == nil || target == nil || iface == nil {
		return "", nil
	}

	key, ok := ipToKey(target)
	if !ok || target.To16() == nil {
		return "", nil
	}

	dst := hostRouteNet(target)
	if dst == nil {
		return "", nil
	}

	route := &netlink.Route{
		LinkIndex: iface.Index,
		Scope:     netlink.SCOPE_LINK,
		Dst:       dst,
	}

	return key, route
}

func (r *routeManager) existingHostRouteMatches(key string, iface *net.Interface) bool {
	if r == nil || iface == nil || key == "" {
		return false
	}

	r.hostMu.Lock()
	defer r.hostMu.Unlock()

	if existing, ok := r.hostRoutes[key]; ok {
		return existing != nil && existing.LinkIndex == iface.Index
	}

	return false
}

func (r *routeManager) recordHostRoute(key string, route *netlink.Route) {
	if r == nil || route == nil || key == "" {
		return
	}

	r.hostMu.Lock()
	r.hostRoutes[key] = route
	r.hostMu.Unlock()
}

func (r *routeManager) logHostRouteError(action, key string, iface *net.Interface, err error) {
	if r == nil || r.log == nil || err == nil {
		return
	}

	ifaceName := ""
	if iface != nil {
		ifaceName = iface.Name
	}

	r.log.Debug(fmt.Sprintf("failed to %s host route", action), "target", key, "iface", ifaceName, "err", err)
}

func (r *routeManager) logHostRouteAttempt(key string, iface *net.Interface) {
	if r == nil || r.log == nil || key == "" {
		return
	}

	ifaceName := ""
	if iface != nil {
		ifaceName = iface.Name
	}

	r.log.Debug("attempt host route install", "target", key, "iface", ifaceName)
}

func (r *routeManager) logHostRouteInstalled(key string, iface *net.Interface) {
	if r == nil || r.log == nil || key == "" {
		return
	}

	ifaceName := ""
	if iface != nil {
		ifaceName = iface.Name
	}

	r.log.Info("installed host route for NDP target", "target", key, "iface", ifaceName)
}

func hostRouteNet(target net.IP) *net.IPNet {
	addr := target.To16()
	if addr == nil {
		return nil
	}

	ipAddr := make(net.IP, net.IPv6len)
	copy(ipAddr, addr)

	mask := net.CIDRMask(ipv6FullMaskBits, ipv6FullMaskBits)

	return &net.IPNet{IP: ipAddr, Mask: mask}
}

func isRouteNotFound(err error) bool {
	if err == nil {
		return false
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.ESRCH || errno == syscall.ENODEV || errno == syscall.ENOENT
	}

	return false
}

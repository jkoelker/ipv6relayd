package netstate

import (
	"fmt"
	"net"
	"strings"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/netutil"
)

// ParseErrorKind differentiates upstream and downstream parsing failures.
type ParseErrorKind int

const (
	// ParseErrorUpstream indicates the upstream link-local string failed to parse.
	ParseErrorUpstream ParseErrorKind = iota
	// ParseErrorDownstream indicates a downstream link-local string failed to parse.
	ParseErrorDownstream
)

// ParseError provides context about link-local parsing failures.
type ParseError struct {
	Kind   ParseErrorKind
	IfName string
	Value  string
}

// Error implements the error interface.
func (e *ParseError) Error() string {
	switch e.Kind {
	case ParseErrorUpstream:
		return fmt.Sprintf("invalid upstream link-local %q", e.Value)
	case ParseErrorDownstream:
		if e.IfName == "" {
			return fmt.Sprintf("invalid downstream link-local %q", e.Value)
		}

		return fmt.Sprintf("invalid downstream %s link-local %q", e.IfName, e.Value)
	default:
		return "invalid link-local configuration"
	}
}

// Link holds parsed link-local overrides and resolves live addresses when needed.
type Link struct {
	interfaceResolver

	upstream    net.IP
	downstreams map[string]net.IP
	cache       *LinkLocalCache
}

// NewLink parses the provided interface configs and returns a Link with cached
// overrides. Options can override the interface address resolver; it defaults to
// SystemInterfaceAddrs.
func NewLink(
	upstream config.InterfaceConfig,
	downstreams []config.InterfaceConfig,
	opts ...func(*Options),
) (*Link, error) {
	cfg := applyOptions(opts)

	store := &Link{
		interfaceResolver: interfaceResolver{},
		downstreams:       make(map[string]net.IP, len(downstreams)),
	}
	store.configureInterfaceAddrs(cfg.interfaceAddrs)
	store.cache = cfg.linkLocalCache
	if store.cache == nil {
		store.cache = NewLinkLocalCache()
	}

	if err := store.assignUpstream(upstream.LinkLocal); err != nil {
		return nil, err
	}

	for _, downstream := range downstreams {
		if err := store.assignDownstream(downstream); err != nil {
			return nil, err
		}
	}

	return store, nil
}

// Upstream returns a cloned copy of the cached upstream override, if any.
func (l *Link) Upstream() net.IP {
	return netutil.CloneAddr(l.upstream)
}

// Downstream returns a cloned copy of the cached downstream override for the provided name.
func (l *Link) Downstream(name string) net.IP {
	if name == "" {
		return nil
	}

	return netutil.CloneAddr(l.downstreams[name])
}

// ResolveUpstream returns the configured upstream link-local or discovers one on the interface.
func (l *Link) ResolveUpstream(ifc *net.Interface) (net.IP, error) {
	if l.upstream != nil {
		return netutil.CloneAddr(l.upstream), nil
	}

	return l.linkLocalAddress(ifc)
}

// ResolveDownstream returns the configured downstream link-local or discovers one on the interface.
func (l *Link) ResolveDownstream(ifc *net.Interface, ifName string) (net.IP, error) {
	if ip := l.Downstream(ifName); ip != nil {
		return ip, nil
	}

	return l.linkLocalAddress(ifc)
}

// InvalidateName evicts the cached entry for the provided interface name.
func (l *Link) InvalidateName(name string) {
	if l == nil || l.cache == nil || name == "" {
		return
	}

	l.cache.InvalidateName(name)
}

// InvalidateIndex evicts the cached entry for the provided interface index.
func (l *Link) InvalidateIndex(index int) {
	if l == nil || l.cache == nil || index == 0 {
		return
	}

	l.cache.InvalidateIndex(index)
}

func (l *Link) assignUpstream(value string) error {
	if strings.TrimSpace(value) == "" {
		l.upstream = nil

		return nil
	}

	ip := netutil.ParseConfiguredIP(value)
	if ip == nil {
		return &ParseError{Kind: ParseErrorUpstream, Value: value}
	}

	l.upstream = netutil.CloneAddr(ip)

	return nil
}

func (l *Link) assignDownstream(cfg config.InterfaceConfig) error {
	if strings.TrimSpace(cfg.LinkLocal) == "" || strings.TrimSpace(cfg.IfName) == "" {
		return nil
	}

	ip := netutil.ParseConfiguredIP(cfg.LinkLocal)
	if ip == nil {
		return &ParseError{Kind: ParseErrorDownstream, IfName: cfg.IfName, Value: cfg.LinkLocal}
	}

	l.downstreams[cfg.IfName] = netutil.CloneAddr(ip)

	return nil
}

func (l *Link) linkLocalAddress(ifc *net.Interface) (net.IP, error) {
	if ifc == nil {
		return nil, ErrNilInterface
	}

	if cached := l.lookupCachedLinkLocal(ifc); cached != nil {
		return cached, nil
	}

	addrs, err := l.resolveInterfaceAddrs(ifc)
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		ip := ipNet.IP
		if ip != nil && ip.IsLinkLocalUnicast() {
			l.storeCachedLinkLocal(ifc, ip)

			return netutil.CloneAddr(ip), nil
		}
	}

	l.invalidateCachedLinkLocal(ifc)

	return nil, fmt.Errorf("%w: %s", ErrNoLinkLocalAddress, ifc.Name)
}

func (l *Link) lookupCachedLinkLocal(ifc *net.Interface) net.IP {
	if l == nil || l.cache == nil || ifc == nil {
		return nil
	}

	return l.cache.Lookup(ifc.Name)
}

func (l *Link) storeCachedLinkLocal(ifc *net.Interface, ip net.IP) {
	if l == nil || l.cache == nil || ifc == nil {
		return
	}

	l.cache.Store(ifc.Name, ifc.Index, ip)
}

func (l *Link) invalidateCachedLinkLocal(ifc *net.Interface) {
	if l == nil || l.cache == nil || ifc == nil {
		return
	}

	if ifc.Name != "" {
		l.cache.InvalidateName(ifc.Name)

		return
	}

	if ifc.Index != 0 {
		l.cache.InvalidateIndex(ifc.Index)
	}
}

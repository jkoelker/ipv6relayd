package netstate

import (
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/jkoelker/ipv6relayd/pkg/netutil"
)

// Hints keeps per-interface address hints and supports parsing and
// discovery helpers shared across services.
type Hints struct {
	interfaceResolver

	mu     sync.RWMutex
	hints  map[string][]net.IP
	filter func(net.IP) bool
}

// NewHints builds a Hints using optional overrides supplied via opts. The
// returned value is safe for concurrent use.
func NewHints(opts ...func(*Options)) *Hints {
	cfg := applyOptions(opts)

	store := &Hints{
		interfaceResolver: interfaceResolver{},
		hints:             netutil.CloneMap(cfg.hintsInitial),
		filter:            cfg.hintsFilter,
	}

	if store.hints == nil {
		store.hints = make(map[string][]net.IP)
	}
	if store.filter == nil {
		store.filter = allowAnyIPv6
	}
	store.configureInterfaceAddrs(cfg.interfaceAddrs)

	return store
}

// CaptureStrings parses the provided user-specified hints and stores them for
// the named interface, overwriting any existing entry.
func (h *Hints) CaptureStrings(name string, values []string) {
	if name == "" {
		return
	}

	if hints := h.parse(values); len(hints) > 0 {
		h.Store(name, hints)
	}
}

// Store replaces the hints for name with a cloned copy of ips.
func (h *Hints) Store(name string, ips []net.IP) {
	if name == "" || len(ips) == 0 {
		return
	}

	h.mu.Lock()
	h.hints[name] = netutil.CloneSlice(ips)
	h.mu.Unlock()
}

// Has reports whether there are stored hints for name.
func (h *Hints) Has(name string) bool {
	if name == "" {
		return false
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	return len(h.hints[name]) > 0
}

// Hints returns a cloned copy of the stored hints for name.
func (h *Hints) Hints(name string) []net.IP {
	if name == "" {
		return nil
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	return netutil.CloneSlice(h.hints[name])
}

// Discover enumerates the addresses on ifc using the configured
// InterfaceAddrsFunc and returns the filtered list.
func (h *Hints) Discover(ifc *net.Interface) ([]net.IP, error) {
	if ifc == nil {
		return nil, ErrNilInterface
	}

	addrs, err := h.resolveInterfaceAddrs(ifc)
	if err != nil {
		return nil, err
	}

	result := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		ip := ipNet.IP
		if ip == nil || ip.To16() == nil {
			continue
		}

		candidate := netutil.CloneAddr(ip)
		if !h.filter(candidate) {
			continue
		}

		result = append(result, candidate)
	}

	return result, nil
}

func (h *Hints) parse(values []string) []net.IP {
	if len(values) == 0 {
		return nil
	}

	result := make([]net.IP, 0, len(values))

	for _, raw := range values {
		val := strings.TrimSpace(raw)
		if val == "" {
			continue
		}

		addr, err := netip.ParseAddr(val)
		if err != nil || !addr.Is6() {
			continue
		}

		candidate := make(net.IP, net.IPv6len)
		copy(candidate, addr.AsSlice())
		if !h.filter(candidate) {
			continue
		}

		result = append(result, candidate)
	}

	return result
}

func allowAnyIPv6(ip net.IP) bool {
	return ip != nil && ip.To16() != nil
}

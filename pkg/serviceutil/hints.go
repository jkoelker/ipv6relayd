package serviceutil

import (
	"log/slog"
	"net"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/netstate"
)

// InterfaceLookup abstracts iface.Manager for easier reuse/testing.
type InterfaceLookup interface {
	ByName(name string) (*net.Interface, error)
}

// HintManager wires netstate.Hints together with interface lookups so
// services can share hint bootstrapping logic.
type HintManager struct {
	store  *netstate.Hints
	ifaces InterfaceLookup
	log    *slog.Logger
}

// NewHintManager builds a HintManager. Methods become no-ops when store is nil.
func NewHintManager(store *netstate.Hints, lookup InterfaceLookup, logger *slog.Logger) *HintManager {
	return &HintManager{store: store, ifaces: lookup, log: logger}
}

// CaptureConfig parses and stores explicit hints for cfg.
func (m *HintManager) CaptureConfig(cfg config.InterfaceConfig) {
	if m == nil || m.store == nil || cfg.IfName == "" {
		return
	}

	m.store.CaptureStrings(cfg.IfName, cfg.AddressHints)
}

// CaptureAll records explicit hints for the upstream and every downstream.
func (m *HintManager) CaptureAll(upstream config.InterfaceConfig, downstreams []config.InterfaceConfig) {
	if m == nil || m.store == nil {
		return
	}

	m.CaptureConfig(upstream)
	for _, downstream := range downstreams {
		m.CaptureConfig(downstream)
	}
}

// Bootstrap ensures hint entries exist by discovering live addresses for the
// upstream and downstream interfaces when missing.
func (m *HintManager) Bootstrap(upstream config.InterfaceConfig, downstreams []config.InterfaceConfig) {
	if m == nil {
		return
	}

	m.Ensure(upstream.IfName)
	for _, downstream := range downstreams {
		m.Ensure(downstream.IfName)
	}
}

// Ensure populates hints for name if absent by querying the interface list.
func (m *HintManager) Ensure(name string) {
	if m == nil || m.store == nil || m.ifaces == nil || name == "" {
		return
	}
	if m.store.Has(name) {
		return
	}

	hints := m.discoverHints(name)
	if len(hints) == 0 {
		return
	}

	m.store.Store(name, hints)
}

// Hints returns a copy of the stored hints for name.
func (m *HintManager) Hints(name string) []net.IP {
	if m == nil || m.store == nil {
		return nil
	}

	return m.store.Hints(name)
}

// DiscoverInterface enumerates interface addresses via the underlying store.
func (m *HintManager) DiscoverInterface(ifc *net.Interface) []net.IP {
	if m == nil || m.store == nil || ifc == nil {
		return nil
	}

	hints, err := m.store.Discover(ifc)
	if err != nil {
		if m.log != nil {
			m.log.Debug("failed to enumerate interface addresses", "iface", ifc.Name, "err", err)
		}

		return nil
	}

	return hints
}

// discoverHints resolves iface by name and enumerates its addresses when possible.
func (m *HintManager) discoverHints(name string) []net.IP {
	ifc, err := m.ifaces.ByName(name)
	if err != nil {
		if m.log != nil {
			m.log.Debug("skip address-hint autodiscovery", "iface", name, "err", err)
		}

		return nil
	}

	hints, err := m.store.Discover(ifc)
	if err != nil {
		if m.log != nil {
			m.log.Debug("failed to enumerate interface addresses", "iface", ifc.Name, "err", err)
		}

		return nil
	}

	return hints
}

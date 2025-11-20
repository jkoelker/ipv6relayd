package iface

import (
	"fmt"
	"net"
	"sync"
)

// Manager caches net.Interface lookups. We refresh entries on demand
// because interface indices can change when links flap.
type Manager struct {
	mu    sync.Mutex
	cache map[string]*net.Interface
}

func NewManager() *Manager {
	return &Manager{
		cache: make(map[string]*net.Interface),
	}
}

// Inject seeds or overrides a cached interface entry. Useful for tests.
func (m *Manager) Inject(name string, ifc *net.Interface) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if name == "" {
		return
	}

	if ifc == nil {
		delete(m.cache, name)

		return
	}

	m.cache[name] = ifc
}

func (m *Manager) ByName(name string) (*net.Interface, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if cached, ok := m.cache[name]; ok && cached != nil {
		return cached, nil
	}

	ifc, err := net.InterfaceByName(name)
	if err != nil {
		delete(m.cache, name)

		return nil, fmt.Errorf("lookup interface %q: %w", name, err)
	}

	m.cache[name] = ifc

	return ifc, nil
}

// Flush removes cached entries. Useful when we detect link-state changes
// via netlink subscriptions.
func (m *Manager) Flush() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cache = make(map[string]*net.Interface)
}

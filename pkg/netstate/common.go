package netstate

import (
	"errors"
	"fmt"
	"net"
)

var (
	// ErrNilInterface indicates a nil *net.Interface was supplied.
	ErrNilInterface = errors.New("nil interface")

	// ErrInterfaceAddressResolverUnset indicates the InterfaceAddrsFunc was nil.
	ErrInterfaceAddressResolverUnset = errors.New("interface address resolver not configured")

	// ErrNoLinkLocalAddress indicates no link-local unicast address was discovered.
	ErrNoLinkLocalAddress = errors.New("no link-local address found")
)

// SystemInterfaceAddrs is the default InterfaceAddrsFunc backed by net.Interface.Addrs.
func SystemInterfaceAddrs(ifc *net.Interface) ([]net.Addr, error) {
	if ifc == nil {
		return nil, ErrNilInterface
	}

	addrs, err := ifc.Addrs()
	if err != nil {
		return nil, fmt.Errorf("list addresses on %s: %w", ifc.Name, err)
	}

	return addrs, nil
}

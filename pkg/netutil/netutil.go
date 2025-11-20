package netutil

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
)

type byteSequence interface {
	~[]byte
}

// CloneAddr returns a copy of addr (for slice-based address types like net.IP or
// net.HardwareAddr). Nil inputs remain nil.
func CloneAddr[T byteSequence](addr T) T {
	if addr == nil {
		return nil
	}

	dup := make(T, len(addr))
	copy(dup, addr)

	return dup
}

// CloneSlice deep copies a slice of address types.
func CloneSlice[T byteSequence](items []T) []T {
	if len(items) == 0 {
		return nil
	}

	dup := make([]T, len(items))
	for i, item := range items {
		dup[i] = CloneAddr(item)
	}

	return dup
}

// CloneMap deep copies a map of interface names to address slices.
func CloneMap[T byteSequence](src map[string][]T) map[string][]T {
	if len(src) == 0 {
		return nil
	}

	dup := make(map[string][]T, len(src))
	for name, hints := range src {
		dup[name] = CloneSlice(hints)
	}

	return dup
}

// ParseConfiguredIP converts a textual IPv6 address into a copied net.IP. It
// returns nil for empty/invalid inputs or non-IPv6 addresses.
func ParseConfiguredIP(value string) net.IP {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	addr, err := netip.ParseAddr(value)
	if err != nil || !addr.Is6() {
		return nil
	}

	bytes := addr.As16()
	ip := make(net.IP, net.IPv6len)
	copy(ip, bytes[:])

	return ip
}

// IsNoDeviceError reports whether err is a net.OpError wrapping ENODEV.
func IsNoDeviceError(err error) bool {
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		return false
	}

	var errno syscall.Errno
	if !errors.As(opErr.Err, &errno) {
		return false
	}

	return errno == syscall.ENODEV
}

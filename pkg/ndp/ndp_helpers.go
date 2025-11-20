package ndp

import (
	"net"
	"net/netip"

	"github.com/mdlayher/ndp"
)

func cloneHardwareAddr(hardwareAddr net.HardwareAddr) net.HardwareAddr {
	if len(hardwareAddr) == 0 {
		return nil
	}

	out := make(net.HardwareAddr, len(hardwareAddr))
	copy(out, hardwareAddr)

	return out
}

func addrToIP(addr netip.Addr) net.IP {
	if !addr.IsValid() {
		return nil
	}

	addrBytes := addr.AsSlice()
	if len(addrBytes) == 0 {
		return nil
	}

	ip := make(net.IP, len(addrBytes))
	copy(ip, addrBytes)

	return ip
}

func ipToAddr(ip net.IP) (netip.Addr, bool) {
	if ip == nil {
		return netip.Addr{}, false
	}

	addr, ok := netip.AddrFromSlice(ip)
	if !ok || !addr.Is6() || addr.Is4In6() {
		return netip.Addr{}, false
	}

	return addr, true
}

func solicitedNodeMulticast(ip net.IP) net.IP {
	addr, ok := ipToAddr(ip)
	if !ok {
		return nil
	}

	snm, err := ndp.SolicitedNodeMulticast(addr)
	if err != nil {
		return nil
	}

	return addrToIP(snm)
}

func newLinkLayerOption(direction ndp.Direction, hw net.HardwareAddr) *ndp.LinkLayerAddress {
	if len(hw) == 0 {
		return nil
	}

	return &ndp.LinkLayerAddress{Direction: direction, Addr: cloneHardwareAddr(hw)}
}

func cloneOptions(options []ndp.Option) []ndp.Option {
	if len(options) == 0 {
		return nil
	}

	cloned := make([]ndp.Option, len(options))
	copy(cloned, options)

	return cloned
}

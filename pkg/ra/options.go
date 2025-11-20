package ra

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/mdlayher/ndp"
)

type routerAdvertisementRewriter struct {
	service    *Service
	downstream *net.Interface
	hasSource  bool
	hasRDNSS   bool
	hasDNSSL   bool
	pref64Idx  int
}

const (
	defaultDNSLifetime            = 600 * time.Second
	maxDNSLPayload                = 2032 // maximum payload that fits in an ND option (255*8 - header)
	ndValidLimit                  = 5400 * time.Second
	unsolicitedLifetimeMultiplier = 2
)

// NDValidLimitSeconds exposes the RFC 9096 recommended ceiling for DNS option lifetimes.
const NDValidLimitSeconds = int64(ndValidLimit / time.Second)

func newRouterAdvertisementRewriter(service *Service, downstream *net.Interface) *routerAdvertisementRewriter {
	if service != nil && service.log == nil {
		service.log = slog.New(slog.DiscardHandler)
	}

	return &routerAdvertisementRewriter{service: service, downstream: downstream}
}

func (r *routerAdvertisementRewriter) Rewrite(msg *ndp.RouterAdvertisement) error {
	if msg == nil {
		return ErrNilRouterAdvertisement
	}

	if err := r.rewritePresentOptions(msg); err != nil {
		return err
	}

	lifetime := r.effectiveDNSLifetime(msg)
	r.appendSynthesizedDNS(msg, lifetime)
	r.ensureSourceLinkLayer(msg)

	return nil
}

func (r *routerAdvertisementRewriter) rewritePresentOptions(msg *ndp.RouterAdvertisement) error {
	options := make([]ndp.Option, 0, len(msg.Options))

	for _, option := range msg.Options {
		if rewritten, handled := r.handleLinkLayerOption(option); handled {
			options = append(options, rewritten)

			continue
		}

		if rewritten, handled := r.handleRDNSSOption(option); handled {
			options = append(options, rewritten)

			continue
		}

		if rewritten, handled := r.handleDNSSLOption(option); handled {
			options = append(options, rewritten)

			continue
		}

		if rewritten, handled := r.handlePref64Option(option); handled {
			options = append(options, rewritten)

			continue
		}

		options = append(options, option)
	}

	msg.Options = options

	return nil
}

func (r *routerAdvertisementRewriter) effectiveDNSLifetime(msg *ndp.RouterAdvertisement) time.Duration {
	lifetime := msg.RouterLifetime
	if lifetime <= 0 {
		lifetime = defaultDNSLifetime
	}

	return clampDNSLifetime(lifetime, r.service)
}

func (r *routerAdvertisementRewriter) appendSynthesizedDNS(msg *ndp.RouterAdvertisement, lifetime time.Duration) {
	if len(r.service.dnsIPs) > 0 && !r.hasRDNSS {
		servers := validNetAddrs(r.service.dnsIPs)
		if len(servers) > 0 {
			msg.Options = append(msg.Options, &ndp.RecursiveDNSServer{
				Lifetime: lifetime,
				Servers:  servers,
			})
		}
	}

	if len(r.service.dnsslDomains) > 0 && !r.hasDNSSL {
		msg.Options = append(msg.Options, &ndp.DNSSearchList{
			Lifetime:    lifetime,
			DomainNames: append([]string(nil), r.service.dnsslDomains...),
		})
	}
}

func (r *routerAdvertisementRewriter) ensureSourceLinkLayer(msg *ndp.RouterAdvertisement) {
	if r.hasSource || len(r.downstream.HardwareAddr) == 0 {
		return
	}

	if !isEthernetAddr(r.downstream.HardwareAddr) {
		return
	}

	msg.Options = append(msg.Options, &ndp.LinkLayerAddress{
		Direction: ndp.Source,
		Addr:      append(net.HardwareAddr(nil), r.downstream.HardwareAddr...),
	})
}

func (r *routerAdvertisementRewriter) rewriteSourceLinkLayer(opt *ndp.LinkLayerAddress) {
	if len(r.downstream.HardwareAddr) == 0 || !isEthernetAddr(r.downstream.HardwareAddr) {
		return
	}

	opt.Addr = append(net.HardwareAddr(nil), r.downstream.HardwareAddr...)
}

func (r *routerAdvertisementRewriter) rewriteRDNSS(opt *ndp.RecursiveDNSServer) {
	if opt.Lifetime > 0 {
		opt.Lifetime = clampDNSLifetime(opt.Lifetime, r.service)
	}

	if len(r.service.dnsIPs) == 0 {
		return
	}

	servers := validNetAddrs(r.service.dnsIPs)
	if len(servers) == 0 {
		return
	}

	opt.Servers = servers
}

func (s *Service) rewriteDNSSLOption(opt *ndp.DNSSearchList) error {
	if opt == nil {
		return fmt.Errorf("%w: dnssl option nil", ErrDNSSLTooShort)
	}

	if len(s.dnsslDomains) == 0 {
		return nil
	}

	if opt.Lifetime > 0 {
		opt.Lifetime = clampDNSLifetime(opt.Lifetime, s)
	}

	opt.DomainNames = append([]string(nil), s.dnsslDomains...)

	return nil
}

func (r *routerAdvertisementRewriter) rewritePref64(opt *ndp.PREF64) error {
	if len(r.service.pref64Entries) == 0 || r.pref64Idx >= len(r.service.pref64Entries) {
		return nil
	}

	entry := r.service.pref64Entries[r.pref64Idx]

	if entry.prefix.Bits() != opt.Prefix.Bits() {
		return fmt.Errorf("%w: expected /%d, rewrite prefix has /%d",
			ErrPref64PrefixMismatch,
			opt.Prefix.Bits(),
			entry.prefix.Bits())
	}

	opt.Prefix = entry.prefix
	opt.Lifetime = clampPref64Lifetime(opt.Lifetime)

	r.pref64Idx++

	return nil
}

func (r *routerAdvertisementRewriter) handleLinkLayerOption(option ndp.Option) (ndp.Option, bool) {
	opt, ok := option.(*ndp.LinkLayerAddress)
	if !ok {
		return nil, false
	}

	if opt.Direction == ndp.Source {
		r.hasSource = true
		r.rewriteSourceLinkLayer(opt)
	}

	return opt, true
}

func (r *routerAdvertisementRewriter) handleRDNSSOption(option ndp.Option) (ndp.Option, bool) {
	opt, ok := option.(*ndp.RecursiveDNSServer)
	if !ok {
		return nil, false
	}

	r.hasRDNSS = true
	r.rewriteRDNSS(opt)

	return opt, true
}

func (r *routerAdvertisementRewriter) handleDNSSLOption(option ndp.Option) (ndp.Option, bool) {
	opt, ok := option.(*ndp.DNSSearchList)
	if !ok {
		return nil, false
	}

	r.hasDNSSL = true
	if err := r.service.rewriteDNSSLOption(opt); err != nil {
		r.service.log.Warn("failed to rewrite DNSSL option", "err", err)
	}

	return opt, true
}

func (r *routerAdvertisementRewriter) handlePref64Option(option ndp.Option) (ndp.Option, bool) {
	opt, ok := option.(*ndp.PREF64)
	if !ok {
		return nil, false
	}

	if err := r.rewritePref64(opt); err != nil {
		r.service.log.Warn("failed to rewrite PREF64 option", "err", err)
	}

	return opt, true
}

type routerSolicitationRewriter struct {
	service     *Service
	upstreamIfc *net.Interface
	hasSource   bool
}

func newRouterSolicitationRewriter(service *Service, upstream *net.Interface) *routerSolicitationRewriter {
	if service != nil && service.log == nil {
		service.log = slog.New(slog.DiscardHandler)
	}

	return &routerSolicitationRewriter{service: service, upstreamIfc: upstream}
}

func (r *routerSolicitationRewriter) Rewrite(msg *ndp.RouterSolicitation) error {
	if msg == nil {
		return ErrNilRouterSolicitation
	}

	options := make([]ndp.Option, 0, len(msg.Options))
	for _, option := range msg.Options {
		lla, ok := option.(*ndp.LinkLayerAddress)
		if !ok || lla.Direction != ndp.Source {
			options = append(options, option)

			continue
		}

		r.hasSource = true
		r.updateRSLinkLayer(lla)
		options = append(options, lla)
	}

	if !r.hasSource && isEthernetAddr(r.upstreamIfc.HardwareAddr) {
		options = append(options, &ndp.LinkLayerAddress{
			Direction: ndp.Source,
			Addr:      append(net.HardwareAddr(nil), r.upstreamIfc.HardwareAddr...),
		})
	}

	msg.Options = options

	return nil
}

func (r *routerSolicitationRewriter) updateRSLinkLayer(opt *ndp.LinkLayerAddress) {
	if len(r.upstreamIfc.HardwareAddr) == 0 || !isEthernetAddr(r.upstreamIfc.HardwareAddr) {
		// Maintain required length with zeros to avoid marshal errors.
		opt.Addr = make(net.HardwareAddr, ethernetAddrLen)

		return
	}

	opt.Addr = append(net.HardwareAddr(nil), r.upstreamIfc.HardwareAddr...)
}

// clampDNSLifetime enforces RFC 8106/9096 guidance that RDNSS/DNSSL lifetimes
// not exceed roughly two RA intervals; we cap at ndValidLimit (90 minutes) and,
// when unsolicited sending is configured, also cap at twice the unsolicited
// interval to avoid advertising longer than we refresh.
func clampDNSLifetime(lifetime time.Duration, svc *Service) time.Duration {
	limit := ndValidLimit

	if svc != nil && svc.unsolicitedMax > 0 {
		if alt := unsolicitedLifetimeMultiplier * svc.unsolicitedMax; alt < limit {
			limit = alt
		}
	}

	if lifetime > limit {
		return limit
	}

	return lifetime
}

func clampPref64Lifetime(lifetime time.Duration) time.Duration {
	maxLifetime := time.Duration(pref64MaxUnits*pref64LifetimeUnits) * time.Second
	if lifetime <= 0 {
		return 0
	}
	if lifetime > maxLifetime {
		return maxLifetime
	}
	// lifetime is encoded in 8 second units; round down to the nearest unit.
	unitSeconds := int64(pref64LifetimeUnits)
	totalSeconds := int64(lifetime / time.Second)
	roundedSeconds := (totalSeconds / unitSeconds) * unitSeconds

	return time.Duration(roundedSeconds) * time.Second
}

func isEthernetAddr(addr net.HardwareAddr) bool {
	return len(addr) == ethernetAddrLen
}

func validNetAddrs(ips []net.IP) []netip.Addr {
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		addr, ok := netip.AddrFromSlice(ip.To16())
		if !ok || addr.Is4() {
			continue
		}
		out = append(out, addr)
	}

	return out
}

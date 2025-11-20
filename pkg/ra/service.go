package ra

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/iface"
	"github.com/jkoelker/ipv6relayd/pkg/ifmon"
	"github.com/jkoelker/ipv6relayd/pkg/netstate"
)

const (
	allNodesMulticast   = "ff02::1"
	allRoutersMulticast = "ff02::2"

	ipv6ChecksumOffset = 2
	multicastHopLimit  = 255
	readBufferSize     = 4096
	// Short read deadline keeps shutdown latency low; sockets are closed on cancel to avoid spin.
	readDeadline = 500 * time.Millisecond

	rsMinPayloadLength              = 6
	RouterAdvertisementHeaderLength = 16
	rsHeaderLength                  = 8
	ethernetAddrLen                 = 6

	pref64BitsMask      = 0x7
	pref64ScaledShift   = 3
	pref64LifetimeUnits = 8

	pref64Len32Bits = 32
	pref64Len40Bits = 40
	pref64Len48Bits = 48
	pref64Len56Bits = 56
	pref64Len64Bits = 64
	pref64Len96Bits = 96

	unsolicitedMinInterval     = 4 * time.Second
	unsolicitedMaxInterval     = 1800 * time.Second
	unsolicitedThreshold       = 9 * time.Second
	unsolicitedMinLowerBound   = 3 * time.Second
	unsolicitedMinUpperPercent = 0.75
	unsolicitedMinDivisor      = 3

	DNSSLHeaderLength               = 8
	pref64HeaderLength              = 16
	maxDNSSLLabelLength             = 63
	optionHeaderLength              = 2
	OptionUnitLength                = 8
	optionTypeSourceLinkLayer       = 1
	RDNSSHeaderLength               = 8
	RDNSSAddressOffset              = RDNSSHeaderLength
	OptionLifetimeOffset            = 4
	OptionLifetimeFieldLen          = 4
	RouterLifetimeOffset            = 6
	routerLifetimeFieldLen          = 2
	prefixInfoOptionLength          = 32
	prefixPreferredLifetimeOffset   = 8
	prefixPreferredLifetimeFieldLen = 4
	minLifetimeOptionLength         = 8
	pref64LifetimeFieldOffset       = 2
	pref64LifetimeFieldLen          = 2

	optionTypePrefixInfo = 3
	optionTypeRouteInfo  = 24
	OptionTypeRDNSS      = 25
	OptionTypeDNSSL      = 31
	optionTypePref64     = 38
)

var (
	ErrServerModeUnsupported    = errors.New("router advertisement server mode is not implemented yet")
	ErrRADownstreamRequired     = errors.New("router advertisements require at least one downstream interface")
	ErrInterfaceEventsRequired  = errors.New("interface events are required")
	ErrUpstreamLinkLocalParse   = errors.New("upstream link-local failed to parse despite validation")
	ErrDownstreamLinkLocalParse = errors.New("downstream link-local failed to parse despite validation")
	ErrServiceAlreadyStarted    = errors.New("router advertisement service already started")
	ErrIPv6PacketConn           = errors.New("failed to obtain ipv6 packet connection")
	ErrUpstreamLinkLocalIPv6    = errors.New("link-local on upstream is not IPv6")
	ErrNilInterface             = netstate.ErrNilInterface
	ErrRouterAdvertisementShort = errors.New("router advertisement too short")
	ErrTruncatedOption          = errors.New("truncated option")
	ErrRouterSolicitationShort  = errors.New("router solicitation too short")
	ErrInvalidMulticastGroup    = errors.New("invalid multicast group")
	ErrLinkLocalNotFound        = netstate.ErrNoLinkLocalAddress
	ErrDNSSLTooShort            = errors.New("dnssl option too short")
	ErrPref64TooShort           = errors.New("pref64 option too short")
	ErrNilRouterAdvertisement   = errors.New("router advertisement is nil")
	ErrNilRouterSolicitation    = errors.New("router solicitation is nil")
	ErrPref64MissingEntry       = errors.New("no pref64 rewrite entry for option index")
	ErrPref64UnknownPLC         = errors.New("unknown pref64 prefix length code")
	ErrPref64PrefixMismatch     = errors.New("pref64 prefix length mismatch")
	ErrPref64NotIPv6            = errors.New("pref64 entry must be IPv6")
	ErrPref64InvalidPrefixLen   = errors.New("pref64 entry must use an allowed prefix length")
	ErrPref64InvalidAddress     = errors.New("pref64 entry invalid IPv6 address")
	ErrDNSSLNoRoom              = errors.New("dnssl option has no room for domains")
	ErrDNSSLOversized           = errors.New("dnssl rewrite exceeds available space")
	ErrDNSSLDomainEmpty         = errors.New("dnssl domain must not be empty")
	ErrDNSSLDomainEmptyLabel    = errors.New("dnssl domain contains empty label")
	ErrDNSSLLabelTooLong        = errors.New("dnssl label exceeds maximum length")
)

func mustParseMulticast(value string) net.IP {
	ip := net.ParseIP(value)
	if ip == nil {
		panic(fmt.Sprintf("invalid multicast constant %q", value))
	}

	return ip
}

type Service struct {
	upstream          config.InterfaceConfig
	downstreams       []config.InterfaceConfig
	cfg               config.RAConfig
	ifaces            *iface.Manager
	log               *slog.Logger
	forwardToUpstream func(ctx context.Context, packetConn *ipv6.PacketConn, upstream *net.Interface, payload []byte) error
	mu                sync.Mutex
	started           bool
	dnsIPs            []net.IP
	dnsslDomains      []string
	pref64Entries     []pref64Entry
	unsolicitedMin    time.Duration
	unsolicitedMax    time.Duration
	lastRA            []byte
	lastRAMu          sync.RWMutex
	lastRAReceived    time.Time
	lastRAExpiry      time.Time

	linkLocals        *netstate.Link
	allNodesIP        net.IP
	allRoutersIP      net.IP
	dhcpv6Enabled     bool
	linkLocalCache    *netstate.LinkLocalCache
	ifaceEvents       <-chan ifmon.InterfaceEvent
	ifaceEventsCancel func()
}

type pref64Entry struct {
	prefix netip.Prefix
	bytes  [12]byte
}

func New(
	upstream config.InterfaceConfig,
	downstreams []config.InterfaceConfig,
	cfg config.RAConfig,
	ifaces *iface.Manager,
	opts ...func(*Options),
) (*Service, error) {
	if err := validateRAInputs(cfg, downstreams); err != nil {
		return nil, err
	}

	clonedDownstreams := append([]config.InterfaceConfig(nil), downstreams...)

	optionCfg := DefaultOptions()
	optionCfg.apply(opts)
	optionCfg.finalize()

	svc := &Service{
		upstream:          upstream,
		downstreams:       clonedDownstreams,
		cfg:               cfg,
		ifaces:            ifaces,
		allNodesIP:        mustParseMulticast(allNodesMulticast),
		allRoutersIP:      mustParseMulticast(allRoutersMulticast),
		log:               optionCfg.Logger,
		dhcpv6Enabled:     optionCfg.DHCPv6Enabled,
		linkLocalCache:    optionCfg.LinkLocalCache,
		ifaceEvents:       optionCfg.InterfaceEvents,
		ifaceEventsCancel: optionCfg.InterfaceEventsCancel,
		forwardToUpstream: optionCfg.ForwardToUpstream,
	}

	if svc.forwardToUpstream == nil {
		svc.forwardToUpstream = svc.forwardRouterSolicitation
	}
	if svc.ifaceEvents == nil {
		return nil, ErrInterfaceEventsRequired
	}

	if svc.log == nil {
		svc.log = slog.New(slog.DiscardHandler).With("component", "ra")
	}

	dnsRewrite := parseDNSRewriteEntries(cfg.DNSRewrite, svc.log)
	dnsslRewrite := normalizeDNSSL(cfg.DNSSearchRewrite, svc.log)

	pref64Rewrite, err := parsePref64Entries(cfg.Pref64Rewrite, svc.log)
	if err != nil {
		return nil, err
	}
	svc.dnsIPs = dnsRewrite
	svc.dnsslDomains = dnsslRewrite
	svc.pref64Entries = pref64Rewrite

	svc.configureUnsolicitedIntervals()

	linkLocals, err := netstate.NewLink(
		upstream,
		downstreams,
		netstate.WithLinkLocalCache(svc.linkLocalCache),
	)
	if err != nil {
		return nil, wrapRALinkLocalError(err)
	}
	svc.linkLocals = linkLocals

	return svc, nil
}

func (s *Service) Name() string {
	return "router-advertisements"
}

func (s *Service) Run(ctx context.Context) error {
	s.mu.Lock()

	if s.started {
		s.mu.Unlock()

		return ErrServiceAlreadyStarted
	}

	s.started = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.started = false
		s.mu.Unlock()
	}()

	runtime, err := newRelayRuntime(s)
	if err != nil {
		return err
	}
	defer runtime.Close()

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	runtime.closeOnContext(runCtx)

	if err := s.startInterfaceEvents(runCtx, runtime.packetConn); err != nil {
		return fmt.Errorf("start interface events: %w", err)
	}
	defer s.stopInterfaceEvents()

	// Ensure multicast memberships/interfaces are current before relying on netlink events.
	s.refreshInterfaceState(runtime.packetConn, "initial startup")

	s.startUnsolicitedLoop(runCtx, runtime.packetConn)

	return runtime.run(runCtx)
}

// LastRACache returns a clone of the cached RA plus receive and expiry times (test visibility).
func (s *Service) LastRACache() ([]byte, time.Time, time.Time) {
	s.lastRAMu.RLock()
	defer s.lastRAMu.RUnlock()

	var last []byte
	if len(s.lastRA) > 0 {
		last = append([]byte(nil), s.lastRA...)
	}

	return last, s.lastRAReceived, s.lastRAExpiry
}

// RewriteRouterAdvertisement rewrites an RA payload for the provided downstream interface.
func (s *Service) RewriteRouterAdvertisement(payload []byte, downstream *net.Interface) ([]byte, error) {
	msg, err := ParseRouterAdvertisementPayload(payload)
	if err != nil {
		return nil, err
	}

	return s.prepareRouterAdvertisement(msg, downstream)
}

// HandleRouterSolicitation validates and forwards a router solicitation upstream. Primarily used by tests.
func (s *Service) HandleRouterSolicitation(
	ctx context.Context,
	packetConn *ipv6.PacketConn,
	upstream *net.Interface,
	payload []byte, // raw payload preserved for tests; rewritten before send
	ctrlMsg *ipv6.ControlMessage,
	src *net.IPAddr,
) error {
	downstreamIfc, downstreamCfg, ok := s.downstreamInterfaceByIndex(ctrlMsg.IfIndex)
	if !ok {
		return nil
	}

	if !s.shouldForwardRouterSolicitation(downstreamIfc, downstreamCfg.Passive, ctrlMsg, src) {
		return nil
	}

	if err := s.forwardToUpstream(ctx, packetConn, upstream, payload); err != nil {
		if errors.Is(err, context.Canceled) {
			s.log.Debug("skip forwarding RS; context canceled")
		} else {
			s.log.Warn("failed forwarding RS upstream", "err", err)
		}

		return err
	}

	return nil
}

// DispatchMessage mirrors the runtime dispatcher without needing the runtime (used in tests).
func (s *Service) DispatchMessage(
	ctx context.Context,
	packetConn *ipv6.PacketConn,
	upstream *net.Interface,
	payload []byte,
	ctrlMsg *ipv6.ControlMessage,
	src *net.IPAddr,
) error {
	if ctrlMsg == nil {
		return nil
	}

	if ctrlMsg.HopLimit != multicastHopLimit {
		s.log.Debug("drop icmpv6 with invalid hop-limit", "hop_limit", ctrlMsg.HopLimit)

		return nil
	}

	switch ipv6.ICMPType(payload[0]) {
	case ipv6.ICMPTypeRouterAdvertisement:
		raMsg, err := ParseRouterAdvertisementPayload(payload)
		if err != nil {
			s.log.Debug("ignore unparsable message", "err", err)

			return nil
		}

		s.handleRouterAdvertisement(ctx, raMsg, ctrlMsg, src, packetConn, upstream)
	case ipv6.ICMPTypeRouterSolicitation:
		// Use raw payload path for tests; forwarder will re-marshal via ndp.
		return s.HandleRouterSolicitation(ctx, packetConn, upstream, payload, ctrlMsg, src)

	default:
		s.log.Debug("ignore non-RA/RS icmpv6 message", "type", ipv6.ICMPType(payload[0]))
	}

	return nil
}

func (s *Service) handleRouterAdvertisement(
	ctx context.Context,
	msg *ndp.RouterAdvertisement,
	ctrlMsg *ipv6.ControlMessage,
	src *net.IPAddr,
	packetConn *ipv6.PacketConn,
	upstream *net.Interface,
) {
	if ctrlMsg != nil && ctrlMsg.HopLimit != multicastHopLimit {
		s.log.Debug("drop RA with invalid hop-limit",
			"hop_limit", ctrlMsg.HopLimit,
			"iface", ctrlMsg.IfIndex)

		return
	}

	if ctrlMsg.IfIndex == upstream.Index {
		s.handleUpstreamRouterAdvertisement(ctx, msg, src, packetConn)

		return
	}

	downstreamIfc, _, ok := s.downstreamInterfaceByIndex(ctrlMsg.IfIndex)
	if !ok {
		s.log.Debug("ignore RA from unmanaged interface", "ifindex", ctrlMsg.IfIndex)

		return
	}

	s.log.Debug("received downstream RA; ignoring", "iface", downstreamIfc.Name, "src", src)
}

func (s *Service) handleUpstreamRouterAdvertisement(
	ctx context.Context,
	msg *ndp.RouterAdvertisement,
	src *net.IPAddr,
	packetConn *ipv6.PacketConn,
) {
	if src != nil && !src.IP.IsLinkLocalUnicast() {
		s.log.Debug("drop RA with non-link-local source", "src", src)

		return
	}

	s.storeLastRA(msg)

	if packetConn == nil {
		return
	}

	if err := s.forwardToDownstreams(ctx, packetConn, msg); err != nil {
		s.log.Warn("failed forwarding RA downstream", "err", err)
	}
}

func (s *Service) shouldForwardRouterSolicitation(
	downstreamIfc *net.Interface,
	downstreamPassive bool,
	ctrlMsg *ipv6.ControlMessage,
	src *net.IPAddr,
) bool {
	if ctrlMsg.HopLimit != multicastHopLimit {
		s.log.Debug("drop RS with invalid hop-limit",
			"hop_limit", ctrlMsg.HopLimit,
			"iface", downstreamIfc.Name)

		return false
	}

	if downstreamPassive {
		return false
	}

	if src != nil && (!src.IP.IsLinkLocalUnicast() && !src.IP.IsUnspecified()) {
		s.log.Debug("drop RS with non-link-local source", "src", src)

		return false
	}

	return true
}

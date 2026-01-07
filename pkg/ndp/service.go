package ndp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mdlayher/ndp"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/ipv6"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/iface"
	"github.com/jkoelker/ipv6relayd/pkg/ifmon"
	"github.com/jkoelker/ipv6relayd/pkg/netstate"
	"github.com/jkoelker/ipv6relayd/pkg/netutil"
	"github.com/jkoelker/ipv6relayd/pkg/serviceutil"
)

const (
	ndAllNodes            = "ff02::1"
	defaultTargetCacheTTL = 30 * time.Minute
	defaultProbeCooldown  = 500 * time.Millisecond
	ndpOptionUnitLen      = 8
	ndpNSHeaderLen        = 24
	ndpNAHeaderLen        = 24
	ndpRedirectHeaderLen  = 40
	ndpOptSourceLL        = 1
	ndpOptTargetLL        = 2
	icmpChecksumOffset    = 2
	multicastHopLimit     = 255
	readBufferLen         = 4096
	// Short read deadline keeps shutdown latency low; sockets are closed on cancel to avoid spin.
	readDeadline          = 500 * time.Millisecond
	linkLayerOptionHeader = 2
	icmpEchoID            = 0x6a6
	icmpEchoSeqMask       = 0xffff
	bitsPerByte           = 8
	ipv6FullMaskBits      = 128
	ndpModeRelay          = "relay"
)

var (
	// ErrUnsupportedNDPMode indicates an unsupported NDP mode was requested.
	ErrUnsupportedNDPMode = errors.New("ndp mode is not supported")
	// ErrInterfaceNotManaged indicates the interface is nil or not tracked.
	ErrInterfaceNotManaged = errors.New("interface not managed")

	// ErrDownstreamRequired indicates the service was configured without any downstream interfaces.
	ErrDownstreamRequired = errors.New("ndp requires downstream interfaces")

	// ErrStaticEntryMissingIface indicates a static entry without an interface.
	ErrStaticEntryMissingIface = errors.New("static entry missing interface")

	// ErrStaticEntryIPv6Only indicates a static prefix that is not IPv6.
	ErrStaticEntryIPv6Only = errors.New("static entry prefix must be IPv6")

	// ErrUpstreamLinkLocalInvalid indicates the upstream link-local address failed to parse.
	ErrUpstreamLinkLocalInvalid = errors.New("upstream link-local failed to parse")

	// ErrDownstreamLinkLocalInvalid indicates a downstream link-local address failed to parse.
	ErrDownstreamLinkLocalInvalid = errors.New("downstream link-local failed to parse")

	// ErrServiceAlreadyRunning indicates the service has already been started.
	ErrServiceAlreadyRunning = errors.New("ndp service already running")

	// ErrIPv6PacketConn indicates creating an IPv6 packet connection failed.
	ErrIPv6PacketConn = errors.New("failed to obtain ipv6 packet connection")

	// ErrNeighborSolicitationShort indicates a truncated neighbor solicitation message.
	ErrNeighborSolicitationShort = errors.New("neighbor solicitation too short")

	// ErrNeighborAdvertisementShort indicates a truncated neighbor advertisement message.
	ErrNeighborAdvertisementShort = errors.New("neighbor advertisement too short")

	// ErrInvalidOptionLength indicates an invalid option length of zero.
	ErrInvalidOptionLength = errors.New("invalid option length 0")

	// ErrOptionTruncated indicates an NDP option that ended prematurely.
	ErrOptionTruncated = errors.New("ndp option truncated")

	// ErrRedirectSourceLinkLocal indicates a redirect source address that is not link-local.
	ErrRedirectSourceLinkLocal = errors.New("redirect source must be link-local unicast")

	// ErrRedirectDestinationMulticast indicates a redirect destination that is multicast.
	ErrRedirectDestinationMulticast = errors.New("redirect destination cannot be multicast")

	// ErrRedirectTargetInvalid indicates a redirect target that is not link-local or destination-matching.
	ErrRedirectTargetInvalid = errors.New("redirect target must be link-local or equal to destination")

	// ErrRedirectNilInterface indicates a missing interface for a redirect request.
	ErrRedirectNilInterface = errors.New("nil interface for redirect")

	// ErrRedirectHostUnspecified indicates we lacked a destination host for a redirect.
	ErrRedirectHostUnspecified = errors.New("redirect destination host unspecified")

	// ErrRedirectMessageTooShort indicates a truncated redirect message.
	ErrRedirectMessageTooShort = errors.New("redirect message too short")

	// ErrNilInterface indicates a nil interface was supplied.
	ErrNilInterface = netstate.ErrNilInterface

	// ErrNoLinkLocalAddress indicates the required link-local address was not found.
	ErrNoLinkLocalAddress = netstate.ErrNoLinkLocalAddress

	// ErrInterfaceAddressResolverUnset indicates the interface address resolver was nil.
	ErrInterfaceAddressResolverUnset = netstate.ErrInterfaceAddressResolverUnset

	// ErrInterfaceEventsRequired indicates the interface events channel was nil.
	ErrInterfaceEventsRequired = errors.New("interface events are required")

	// ErrInterfaceManagerRequired indicates the interface manager was nil.
	ErrInterfaceManagerRequired = errors.New("interface manager is required")
)

type Service struct {
	upstream    config.InterfaceConfig
	downstreams []config.InterfaceConfig
	cfg         config.NDPConfig
	ifaces      *iface.Manager
	log         *slog.Logger

	mu                sync.Mutex
	started           bool
	targetCache       *targetCache
	staticBindings    []staticBinding
	downstreamConfigs map[string]config.InterfaceConfig
	routes            *routeManager
	linkLocals        *netstate.Link
	hints             *serviceutil.HintManager
	probeMu           sync.Mutex
	lastProbe         map[string]time.Time
	probeCooldown     time.Duration
	interfaceAddrs    func(*net.Interface) ([]net.Addr, error)
	neighborResolver  func(*net.Interface, net.IP) (net.HardwareAddr, error)
	allNodesIP        net.IP // cached ff02::1 to avoid repeated parsing
	initialHints      map[string][]net.IP
	packetConn        atomic.Pointer[ipv6.PacketConn]
	linkLocalCache    *netstate.LinkLocalCache
	ifaceEvents       <-chan ifmon.InterfaceEvent
	ifaceEventsCancel func()
}

type targetEntry struct {
	iface      string
	lastSeen   time.Time
	lastHostIP net.IP
}

type staticBinding struct {
	prefix netip.Prefix
	iface  string
}

func allowNDPHint(ip net.IP) bool {
	return ip != nil && ip.To16() != nil && !ip.IsUnspecified() && !ip.IsMulticast()
}

func cloneHostHint(ip net.IP) net.IP {
	if allowNDPHint(ip) {

		return netutil.CloneAddr(ip)
	}

	return nil
}

func validateNDPMode(cfg config.NDPConfig, downstreams []config.InterfaceConfig) error {
	switch cfg.Mode {
	case ndpModeRelay:
	default:

		return fmt.Errorf("%w: %q", ErrUnsupportedNDPMode, cfg.Mode)
	}

	if len(downstreams) == 0 {

		return ErrDownstreamRequired
	}

	return nil
}

func buildStaticBindings(entries []config.NDPStaticBinding) ([]staticBinding, error) {
	bindings := make([]staticBinding, 0, len(entries))

	for idx, entry := range entries {
		if strings.TrimSpace(entry.Interface) == "" {

			return nil, fmt.Errorf("%w: entry %d", ErrStaticEntryMissingIface, idx)
		}

		prefix, err := netip.ParsePrefix(entry.Prefix)
		if err != nil {

			return nil, fmt.Errorf("static entry %d invalid prefix: %w", idx, err)
		}

		if !prefix.Addr().Is6() {

			return nil, fmt.Errorf("%w: entry %d", ErrStaticEntryIPv6Only, idx)
		}

		bindings = append(bindings, staticBinding{
			prefix: prefix.Masked(),
			iface:  entry.Interface,
		})
	}

	return bindings, nil
}

func indexDownstreamConfigs(downstreams []config.InterfaceConfig) map[string]config.InterfaceConfig {
	indexed := make(map[string]config.InterfaceConfig, len(downstreams))

	for _, downstream := range downstreams {
		if downstream.IfName == "" {

			continue
		}

		indexed[downstream.IfName] = downstream
	}

	return indexed
}

func New(
	upstream config.InterfaceConfig,
	downstreams []config.InterfaceConfig,
	cfg config.NDPConfig,
	ifaces *iface.Manager,
	opts ...func(*Options),
) (*Service, error) {
	clonedDownstreams := append([]config.InterfaceConfig(nil), downstreams...)

	optionCfg := DefaultOptions()
	optionCfg.apply(opts)
	optionCfg.finalize()
	if optionCfg.InterfaceManager == nil {
		optionCfg.InterfaceManager = ifaces
	}

	svc := &Service{
		upstream:          upstream,
		downstreams:       clonedDownstreams,
		cfg:               cfg,
		ifaces:            optionCfg.InterfaceManager,
		log:               optionCfg.Logger,
		downstreamConfigs: indexDownstreamConfigs(clonedDownstreams),
		lastProbe:         make(map[string]time.Time),
		probeCooldown:     defaultProbeCooldown,
		interfaceAddrs:    optionCfg.InterfaceAddrs,
		neighborResolver:  optionCfg.NeighborResolver,
		allNodesIP:        net.ParseIP(ndAllNodes),
		linkLocalCache:    optionCfg.LinkLocalCache,
		ifaceEvents:       optionCfg.InterfaceEvents,
		ifaceEventsCancel: optionCfg.InterfaceEventsCancel,
		initialHints:      optionCfg.AddressHints,
	}

	if svc.ifaces == nil {
		return nil, ErrInterfaceManagerRequired
	}

	if svc.ifaceEvents == nil {
		return nil, ErrInterfaceEventsRequired
	}

	targetTTL := defaultTargetCacheTTL
	if svc.cfg.TargetCacheTTL > 0 {
		targetTTL = svc.cfg.TargetCacheTTL
	}

	svc.targetCache = newTargetCache(targetTTL, func(key string) {
		svc.removeExpiredHostRoutes([]string{key})
	})

	if svc.routes == nil {
		svc.routes = newRouteManager(svc.log)
	} else if svc.routes.log == nil {
		svc.routes.log = svc.log
	}

	if err := validateNDPMode(svc.cfg, svc.downstreams); err != nil {
		return nil, err
	}

	staticBindings, err := buildStaticBindings(svc.cfg.StaticEntries)
	if err != nil {
		return nil, err
	}
	svc.staticBindings = staticBindings
	svc.downstreamConfigs = indexDownstreamConfigs(svc.downstreams)

	svc.setupHintManager()

	if err := svc.setupLinkLocals(); err != nil {
		return nil, err
	}

	return svc, nil
}

// PrepareRedirect rewrites the redirect payload with updated link-layer options.
func (s *Service) PrepareRedirect(payload []byte, iface *net.Interface, targetHW net.HardwareAddr) ([]byte, error) {
	if len(payload) < ndpRedirectHeaderLen {

		return nil, ErrRedirectMessageTooShort
	}

	out := append([]byte(nil), payload...)
	sourceMAC := iface.HardwareAddr
	targetMAC := redirectTargetHardware(iface, targetHW)

	hasSource, hasTarget, err := rewriteRedirectOptions(out, sourceMAC, targetMAC)
	if err != nil {

		return nil, err
	}

	if len(targetMAC) == 0 {
		out, err = dropNDPOptions(out, ndpRedirectHeaderLen, ndpOptTargetLL)
		if err != nil {

			return nil, err
		}
	}

	if len(sourceMAC) > 0 && !hasSource {
		out = append(out, encodeLinkLayerOption(ndpOptSourceLL, sourceMAC)...)
	}

	if len(targetMAC) > 0 && !hasTarget {
		out = append(out, encodeLinkLayerOption(ndpOptTargetLL, targetMAC)...)
	}

	return out, nil
}

// BootstrapAddressHints fills missing hint entries using live interface data.
func (s *Service) BootstrapAddressHints() {
	if s.hints == nil {
		return
	}

	s.hints.Bootstrap(s.upstream, s.downstreams)
}

// AddressHints returns a copy of the stored hints for the requested interface.
func (s *Service) AddressHints(name string) []net.IP {
	if s.hints == nil {
		return nil
	}

	return s.hints.Hints(name)
}

func (s *Service) Name() string { return "ndp" }

// LookupTargetHostIP returns a cloned host IP for the given target if present in the cache.
func (s *Service) LookupTargetHostIP(target net.IP) net.IP {
	return s.lookupTargetHostIP(target)
}

// ResolveRedirectTargetHardware exposes redirect target resolution.
func (s *Service) ResolveRedirectTargetHardware(target net.IP, iface *net.Interface) net.HardwareAddr {
	return s.resolveRedirectTargetHardware(target, iface)
}

// SendRedirect exposes the redirect sender.
func (s *Service) SendRedirect(
	packetConn *ipv6.PacketConn,
	payload []byte,
	iface *net.Interface,
	dest net.IP,
	target net.IP,
) error {
	return s.sendRedirect(packetConn, payload, iface, dest, target)
}

// SeedTargetCache inserts a target cache entry; intended for tests.
func (s *Service) SeedTargetCache(target net.IP, hostIP net.IP, iface string) {
	if s.targetCache == nil {
		return
	}

	key, ok := ipToKey(target)
	if !ok {
		return
	}

	s.targetCache.seed(key, targetEntry{
		iface:      iface,
		lastSeen:   time.Now(),
		lastHostIP: cloneHostHint(hostIP),
	})
}

// seedTargets populates the target cache from the kernel's neighbor table.
// This allows the relay to pick up existing clients if it starts after they
// have already completed DAD and address acquisition.
func (s *Service) seedTargets(upstream *net.Interface, downstreams []*net.Interface) {
	if s.log != nil {
		s.log.Info("seeding ndp target cache from neighbor table")
	}

	validStates := netlink.NUD_REACHABLE | netlink.NUD_STALE | netlink.NUD_DELAY | netlink.NUD_PROBE | netlink.NUD_PERMANENT

	for _, downstream := range downstreams {
		neighs, err := netlink.NeighList(downstream.Index, netlink.FAMILY_V6)
		if err != nil {
			if s.log != nil {
				s.log.Warn("failed to list neighbors for seeding", "iface", downstream.Name, "err", err)
			}
			continue
		}

		for _, neigh := range neighs {
			if neigh.State&validStates == 0 {
				continue
			}

			if neigh.IP == nil || !neigh.IP.IsGlobalUnicast() {
				continue
			}

			if s.log != nil {
				s.log.Debug("seeding target from neighbor table", "target", neigh.IP, "iface", downstream.Name)
			}

			// We pass nil for hostIP and packetConn because we are not
			// reacting to a packet, just learning the route. trackTarget
			// handles nil packetConn gracefully (it just skips the immediate unicast probe).
			s.trackTarget(neigh.IP, nil, downstream, upstream, nil)
		}
	}
}

// ForEachDownstream invokes optionHandler for every downstream interface, returning the first error encountered.
func (s *Service) ForEachDownstream(downstreams []*net.Interface, optionHandler func(*net.Interface) error) error {
	var firstErr error

	for _, downstream := range downstreams {
		if err := optionHandler(downstream); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if firstErr != nil {

		return fmt.Errorf("refresh multicast: %w", firstErr)
	}

	return nil
}

func (s *Service) setupHintManager() {
	hintStore := netstate.NewHints(
		netstate.WithInterfaceAddrsFunc(s.interfaceAddrs),
		netstate.WithInitialHints(cloneAddressHints(s.initialHints)),
		netstate.WithHintsFilter(allowNDPHint),
	)
	s.hints = serviceutil.NewHintManager(hintStore, s.ifaces, s.log)
	s.initialHints = nil

	if s.hints != nil {
		s.hints.CaptureAll(s.upstream, s.downstreams)
		s.hints.Bootstrap(s.upstream, s.downstreams)
	}
}

func (s *Service) setupLinkLocals() error {
	linkLocals, err := netstate.NewLink(
		s.upstream,
		s.downstreams,
		netstate.WithInterfaceAddrsFunc(s.interfaceAddrs),
		netstate.WithLinkLocalCache(s.linkLocalCache),
	)
	if err != nil {
		return wrapNDPLinkLocalError(err)
	}

	s.linkLocals = linkLocals

	return nil
}

func (s *Service) tryStart() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return false
	}

	s.started = true

	return true
}

func (s *Service) finishRun() {
	s.mu.Lock()
	s.started = false
	s.mu.Unlock()
}

func (s *Service) forwardToUpstream(
	packetConn *ipv6.PacketConn,
	upstream *net.Interface,
	msg *ndp.NeighborSolicitation,
	controlMessage *ipv6.ControlMessage,
	src net.Addr,
) error {
	dst := &net.IPAddr{IP: controlMessage.Dst}
	if dst.IP == nil || dst.IP.IsUnspecified() {
		dst.IP = s.allNodesIP
	}

	prepared, err := s.prepareNeighborSolicitation(msg, upstream, src)
	if err != nil {

		return err
	}

	ctrl := &ipv6.ControlMessage{
		IfIndex:  upstream.Index,
		HopLimit: multicastHopLimit,
	}
	if _, err := packetConn.WriteTo(prepared, ctrl, dst); err != nil {
		s.handleWriteError(err)

		return fmt.Errorf("send upstream on %s: %w", upstream.Name, err)
	}

	return nil
}

func (s *Service) forwardToDownstreams(
	packetConn *ipv6.PacketConn,
	msg *ndp.NeighborAdvertisement,
	controlMessage *ipv6.ControlMessage,
	downstreams []*net.Interface,
) error {
	var errs []error

	for _, downstream := range downstreams {
		if err := s.forwardAdvertisementToDownstream(packetConn, msg, controlMessage, downstream); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("forward to downstreams: %w", errors.Join(errs...))
	}

	return nil
}

func (s *Service) prepareNeighborSolicitation(
	msg *ndp.NeighborSolicitation,
	iface *net.Interface,
	src net.Addr,
) ([]byte, error) {
	if msg == nil {
		return nil, ErrNeighborSolicitationShort
	}

	prepared := *msg
	prepared.Options = cloneOptions(msg.Options)
	hardwareAddr := iface.HardwareAddr
	hasSource := false

	for idx, opt := range prepared.Options {
		lla, ok := opt.(*ndp.LinkLayerAddress)
		if !ok || lla.Direction != ndp.Source {
			continue
		}

		hasSource = true
		if replacement := newLinkLayerOption(ndp.Source, hardwareAddr); replacement != nil {
			prepared.Options[idx] = replacement
		}
	}

	if allowSourceOption(src) && !hasSource {
		if opt := newLinkLayerOption(ndp.Source, hardwareAddr); opt != nil {
			prepared.Options = append(prepared.Options, opt)
		}
	}

	payload, err := ndp.MarshalMessage(&prepared)
	if err != nil {
		return nil, fmt.Errorf("marshal neighbor solicitation: %w", err)
	}

	return payload, nil
}

func (s *Service) prepareNeighborAdvertisement(
	msg *ndp.NeighborAdvertisement,
	iface *net.Interface,
) ([]byte, error) {
	if msg == nil {
		return nil, ErrNeighborAdvertisementShort
	}

	prepared := *msg
	prepared.Options = cloneOptions(msg.Options)
	hardwareAddr := iface.HardwareAddr
	hasTarget := false

	for idx, opt := range prepared.Options {
		lla, ok := opt.(*ndp.LinkLayerAddress)
		if !ok || lla.Direction != ndp.Target {
			continue
		}

		hasTarget = true
		if replacement := newLinkLayerOption(ndp.Target, hardwareAddr); replacement != nil {
			prepared.Options[idx] = replacement
		}
	}

	if !hasTarget {
		if opt := newLinkLayerOption(ndp.Target, hardwareAddr); opt != nil {
			prepared.Options = append(prepared.Options, opt)
		}
	}

	payload, err := ndp.MarshalMessage(&prepared)
	if err != nil {
		return nil, fmt.Errorf("marshal neighbor advertisement: %w", err)
	}

	return payload, nil
}

func ifaceNames(ifcs []*net.Interface) []string {
	names := make([]string, 0, len(ifcs))
	for _, ifc := range ifcs {
		names = append(names, ifc.Name)
	}

	return names
}

func (s *Service) handleWriteError(err error) {
	if !netutil.IsNoDeviceError(err) {

		return
	}

	s.ifaces.Flush()
}

func (s *Service) startInterfaceEvents(ctx context.Context) error {
	if s.ifaceEvents == nil {
		return ErrInterfaceEventsRequired
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-s.ifaceEvents:
				if !ok {
					return
				}
				s.refreshMonitorState(ev.Reason, ev.IfIndex, ev.IfName)
			}
		}
	}()

	return nil
}

func (s *Service) stopInterfaceEvents() {
	if s.ifaceEventsCancel != nil {
		s.ifaceEventsCancel()
		s.ifaceEventsCancel = nil
	}
}

func (s *Service) refreshMonitorState(reason string, _ int, _ string) {
	s.ifaces.Flush()

	if s.log != nil {
		s.log.Debug("ndp interface refresh", "reason", reason)
	}
}

func (s *Service) installStaticRoutes() error {
	if len(s.staticBindings) == 0 {

		return nil
	}

	if s.routes == nil {

		return nil
	}

	s.routes.staticMu.Lock()
	defer s.routes.staticMu.Unlock()

	s.routes.cleanupStaticRoutesLocked()

	var errs []error

	for _, binding := range s.staticBindings {
		if binding.iface == "" {

			continue
		}

		ifc, err := s.ifaces.ByName(binding.iface)
		if err != nil {
			errs = append(errs, fmt.Errorf("lookup interface %s: %w", binding.iface, err))

			continue
		}

		dst := prefixToIPNet(binding.prefix)
		route := &netlink.Route{
			LinkIndex: ifc.Index,
			Scope:     netlink.SCOPE_LINK,
			Dst:       dst,
		}

		if err := netlink.RouteReplace(route); err != nil {
			errs = append(errs, fmt.Errorf("install route %s via %s: %w", dst, ifc.Name, err))

			continue
		}

		s.routes.appendStaticRouteLocked(route)
	}

	if len(errs) > 0 {

		return fmt.Errorf("install static routes: %w", errors.Join(errs...))
	}

	return nil
}

func (s *Service) cleanupStaticRoutes() {
	if s.routes == nil {
		return
	}

	s.routes.cleanupStaticRoutes()
}

func prefixToIPNet(prefix netip.Prefix) *net.IPNet {
	masked := prefix.Masked()
	addr := masked.Addr()
	ipAddr := make(net.IP, net.IPv6len)
	value := addr.As16()
	copy(ipAddr, value[:])

	mask := net.CIDRMask(masked.Bits(), net.IPv6len*bitsPerByte)

	return &net.IPNet{IP: ipAddr, Mask: mask}
}

func defaultNeighborHardware(iface *net.Interface, ipAddr net.IP) (net.HardwareAddr, error) {
	if iface == nil || ipAddr == nil || len(ipAddr) == 0 || ipAddr.IsUnspecified() {

		return nil, nil
	}

	neighs, err := netlink.NeighList(iface.Index, netlink.FAMILY_V6)
	if err != nil {

		return nil, fmt.Errorf("list neighbors on %s: %w", iface.Name, err)
	}

	for _, neigh := range neighs {
		if neigh.IP == nil || len(neigh.HardwareAddr) == 0 {

			continue
		}

		if ipAddr.Equal(neigh.IP) {

			return netutil.CloneAddr(neigh.HardwareAddr), nil
		}
	}

	return nil, nil
}

func (s *Service) ensureHostRoute(target net.IP, iface *net.Interface) {
	if s.routes == nil {

		return
	}

	s.routes.ensureHostRoute(target, iface)
}

func (s *Service) cleanupHostRoutes() {
	if s.routes != nil {
		s.routes.cleanupHostRoutes()
	}
}

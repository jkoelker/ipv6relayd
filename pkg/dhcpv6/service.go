package dhcpv6

import (
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/rfc1035label"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/iface"
	"github.com/jkoelker/ipv6relayd/pkg/ifmon"
	"github.com/jkoelker/ipv6relayd/pkg/netstate"
	"github.com/jkoelker/ipv6relayd/pkg/serviceutil"
)

const (
	serverPort     = 547
	clientPort     = 546
	mcastAddr      = "ff02::1:2"
	readBufferSize = 8192
	// Short read deadline keeps shutdown latency low; sockets are closed on cancel to avoid spin.
	readDeadlineInterval   = 500 * time.Millisecond
	defaultHopLimit        = 64
	multicastRelayHopLimit = 8

	// ServerPort is the UDP port used by DHCPv6 servers.
	ServerPort = serverPort

	// ClientPort is the UDP port used by DHCPv6 clients.
	ClientPort = clientPort

	// DefaultHopLimit is the hop limit applied to unicast relay traffic.
	DefaultHopLimit = defaultHopLimit

	// MaxHopCount is the maximum hop count for DHCPv6 relay messages.
	MaxHopCount = 8

	// MulticastRelayHopLimit constrains relay multicast to the local link.
	MulticastRelayHopLimit = multicastRelayHopLimit

	// Cache window for per-client link-layer lookups.
	defaultClientCacheTTL = 5 * time.Minute
	defaultTransactionTTL = 2 * time.Minute
)

var (
	ErrInterfaceNotManaged      = errors.New("interface not managed")
	ErrServiceAlreadyStarted    = errors.New("dhcpv6 service already started")
	ErrUpstreamLinkLocalParse   = errors.New("upstream link-local parse failure")
	ErrDownstreamLinkLocalParse = errors.New("downstream link-local parse failure")
	ErrInvalidMulticastConst    = errors.New("invalid multicast constant")
	ErrLinkAddressRequired      = errors.New("link-address required when interface-id is disabled")
	ErrMissingRelayMessageOpt   = errors.New("missing relay message option")
	ErrMissingPeerAddress       = errors.New("missing peer-address in relay-reply")
	ErrUnexpectedRelayPayload   = errors.New("unexpected inner relay type")
	ErrDownstreamInterface      = errors.New("unable to determine downstream interface")
	ErrUnexpectedAddrType       = errors.New("unexpected addr type")
	ErrEmptyUpstreamValue       = errors.New("resolve upstream: value must not be empty")
	ErrNoIPv6Gateway            = errors.New("no IPv6 default route with gateway found on upstream")
	ErrUpstreamInterfaceNeeded  = errors.New("upstream interface is required")
	ErrInterfaceEventsNeeded    = errors.New("interface events are required")
	ErrInterfaceManagerNeeded   = errors.New("interface manager is required")
	ErrUpstreamNotConfigured    = errors.New("upstream not configured")
)

type upstreamResolverFunc func(config.InterfaceConfig, config.DHCPv6Config, *iface.Manager) (*net.UDPAddr, bool, error)

type Service struct {
	upstreamIface config.InterfaceConfig
	downstreams   []config.InterfaceConfig
	cfg           config.DHCPv6Config
	ifaces        *iface.Manager
	log           *slog.Logger

	dnsOverride   []net.IP
	dnsslOverride *rfc1035label.Labels

	upstreamMu   sync.RWMutex
	upstreamAddr *net.UDPAddr

	determineUpstream    upstreamResolverFunc
	autoDiscoverUpstream bool

	mu           sync.Mutex
	started      bool
	transactions *transactionCache

	clientCache *clientCache

	clientCacheTTL time.Duration
	transactionTTL time.Duration

	linkLocals        *netstate.Link
	multicastIP       net.IP
	hints             *serviceutil.HintManager
	interfaceAddrs    func(*net.Interface) ([]net.Addr, error)
	linkLocalCache    *netstate.LinkLocalCache
	ifaceEvents       <-chan ifmon.InterfaceEvent
	ifaceEventsCancel func()

	initialHints map[string][]net.IP

	remoteIDLogOnce sync.Once
}

func New(
	upstream config.InterfaceConfig,
	downstreams []config.InterfaceConfig,
	cfg config.DHCPv6Config,
	ifaces *iface.Manager,
	opts ...func(*Options),
) (*Service, error) {
	clonedDownstreams := append([]config.InterfaceConfig(nil), downstreams...)

	optionCfg := DefaultOptions()
	optionCfg.apply(opts)
	optionCfg.finalize()

	effectiveUpstream := selectInterfaceConfig(upstream, optionCfg.UpstreamInterface)
	effectiveDownstreams := selectDownstreams(clonedDownstreams, optionCfg.DownstreamInterfaces)
	effectiveCfg := selectDHCPv6Config(cfg, optionCfg.ConfigOverride)
	manager := selectInterfaceManager(ifaces, optionCfg.InterfaceManager)
	transactionTTL := pickDuration(optionCfg.TransactionTTL, defaultTransactionTTL)

	svc := &Service{
		upstreamIface:     effectiveUpstream,
		downstreams:       effectiveDownstreams,
		cfg:               effectiveCfg,
		ifaces:            manager,
		log:               optionCfg.Logger,
		interfaceAddrs:    optionCfg.InterfaceAddrs,
		clientCacheTTL:    defaultClientCacheTTL,
		transactionTTL:    transactionTTL,
		dnsOverride:       optionCfg.DNSOverride,
		dnsslOverride:     optionCfg.DNSSearchLabels,
		initialHints:      optionCfg.InitialHints,
		linkLocals:        optionCfg.LinkLocals,
		linkLocalCache:    optionCfg.LinkLocalCache,
		ifaceEvents:       optionCfg.InterfaceEvents,
		ifaceEventsCancel: optionCfg.InterfaceEventsCancel,
		determineUpstream: optionCfg.UpstreamResolver,
	}

	applyUpstreamOverride(svc, optionCfg.UpstreamAddr)

	if err := svc.configure(); err != nil {
		return nil, err
	}

	if svc.clientCacheTTL <= 0 {
		svc.clientCacheTTL = defaultClientCacheTTL
	}

	if svc.transactionTTL <= 0 {
		svc.transactionTTL = defaultTransactionTTL
	}

	svc.clientCache = newClientCache(svc.clientCacheTTL)
	svc.transactions = newTransactionCache(svc.transactionTTL)

	if err := svc.initialize(); err != nil {
		return nil, err
	}

	return svc, nil
}

func selectInterfaceConfig(base config.InterfaceConfig, override *config.InterfaceConfig) config.InterfaceConfig {
	if override == nil {
		return base
	}

	return *override
}

func selectDownstreams(base []config.InterfaceConfig, override []config.InterfaceConfig) []config.InterfaceConfig {
	if len(override) == 0 {
		return base
	}

	return append([]config.InterfaceConfig(nil), override...)
}

func selectDHCPv6Config(base config.DHCPv6Config, override *config.DHCPv6Config) config.DHCPv6Config {
	if override == nil {
		return base
	}

	return *override
}

func selectInterfaceManager(base, override *iface.Manager) *iface.Manager {
	if override != nil {
		return override
	}

	return base
}

func pickDuration(override, fallback time.Duration) time.Duration {
	if override > 0 {
		return override
	}

	return fallback
}

func applyUpstreamOverride(svc *Service, addr *net.UDPAddr) {
	if addr == nil {
		return
	}

	svc.setUpstream(addr)
}

func (s *Service) Name() string {
	return "dhcpv6"
}

func (s *Service) configure() error {
	if s.ifaceEvents == nil {
		return ErrInterfaceEventsNeeded
	}
	if s.ifaceEventsCancel == nil {
		s.ifaceEventsCancel = func() {}
	}

	if s.ifaces == nil {
		return ErrInterfaceManagerNeeded
	}

	if s.interfaceAddrs == nil {
		s.interfaceAddrs = netstate.SystemInterfaceAddrs
	}

	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler).With("component", "dhcpv6")
	}

	s.applyDNSDefaults()

	if s.determineUpstream == nil {
		s.determineUpstream = determineDHCPv6Upstream
	}

	return nil
}

func (s *Service) initialize() error {
	if err := s.ensureUpstreamConfigured(); err != nil {
		return err
	}

	s.setupHintManager()

	return s.setupLinkLocals()
}

func (s *Service) applyDNSDefaults() {
	if len(s.dnsOverride) == 0 {
		if defaults := normalizeDNSOverride(s.cfg.OverrideDNS, s.log); len(defaults) > 0 {
			s.dnsOverride = defaults
		}
	}

	if s.dnsslOverride == nil {
		s.dnsslOverride = buildDomainSearchLabels(s.cfg.OverrideDNSSearch, s.log)
	}
}

func (s *Service) ensureUpstreamConfigured() error {
	if s.upstreamAddr != nil {
		return nil
	}

	resolver := s.determineUpstream
	if resolver == nil {
		resolver = determineDHCPv6Upstream
	}

	upstream, autodiscovered, err := resolver(s.upstreamIface, s.cfg, s.ifaces)
	if err != nil {
		if errors.Is(err, ErrNoIPv6Gateway) {
			upstream = fallbackMulticastUpstream(s.upstreamIface.IfName)
			autodiscovered = true
		} else {
			return err
		}
	}

	s.setUpstream(upstream)
	s.autoDiscoverUpstream = autodiscovered
	if !autodiscovered {
		return nil
	}

	current := s.currentUpstream()
	if current == nil {
		return nil
	}

	s.log.Info(
		"auto-discovered dhcpv6 upstream",
		"ifname", s.upstreamIface.IfName,
		"upstream", current.String(),
	)

	return nil
}

func (s *Service) setupHintManager() {
	hintStore := netstate.NewHints(
		netstate.WithInterfaceAddrsFunc(s.interfaceAddrs),
		netstate.WithHintsFilter(isUsableLinkAddress),
		netstate.WithInitialHints(cloneAddressHints(s.initialHints)),
	)
	s.hints = serviceutil.NewHintManager(hintStore, s.ifaces, s.log)
	s.initialHints = nil

	if s.hints != nil {
		s.hints.Bootstrap(s.upstreamIface, s.downstreams)
		s.hints.CaptureAll(s.upstreamIface, s.downstreams)
	}
}

func (s *Service) setupLinkLocals() error {
	if s.linkLocals != nil {
		return nil
	}

	linkLocals, err := netstate.NewLink(
		s.upstreamIface,
		s.downstreams,
		netstate.WithInterfaceAddrsFunc(s.interfaceAddrs),
		netstate.WithLinkLocalCache(s.linkLocalCache),
	)
	if err != nil {
		return wrapDHCPLinkLocalError(err)
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

func (s *Service) refreshUpstream(reason string) error {
	if !s.autoDiscoverUpstream {
		return nil
	}

	resolver := s.determineUpstream
	if resolver == nil {
		resolver = determineDHCPv6Upstream
	}

	upstream, autodiscovered, err := resolver(s.upstreamIface, s.cfg, s.ifaces)
	if err != nil {
		if errors.Is(err, ErrNoIPv6Gateway) {
			upstream = fallbackMulticastUpstream(s.upstreamIface.IfName)
			autodiscovered = true
		} else {
			return err
		}
	}

	s.autoDiscoverUpstream = autodiscovered
	if !autodiscovered {
		return nil
	}

	prev, changed := s.swapUpstream(upstream)
	if changed {
		s.log.Info(
			"dhcpv6 upstream updated",
			"reason", reason,
			"previous", udpAddrString(prev),
			"next", udpAddrString(upstream),
		)
	}

	return nil
}

func (s *Service) swapUpstream(newAddr *net.UDPAddr) (*net.UDPAddr, bool) {
	s.upstreamMu.Lock()
	defer s.upstreamMu.Unlock()

	if udpAddrEqual(s.upstreamAddr, newAddr) {
		return nil, false
	}

	prev := cloneUDPAddr(s.upstreamAddr)
	s.upstreamAddr = cloneUDPAddr(newAddr)

	return prev, true
}

func (s *Service) setUpstream(addr *net.UDPAddr) {
	s.upstreamMu.Lock()
	s.upstreamAddr = cloneUDPAddr(addr)
	s.upstreamMu.Unlock()
}

func (s *Service) currentUpstream() *net.UDPAddr {
	s.upstreamMu.RLock()
	defer s.upstreamMu.RUnlock()

	return cloneUDPAddr(s.upstreamAddr)
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}

	clone := *addr
	if addr.IP != nil {
		clone.IP = append(net.IP(nil), addr.IP...)
	}

	return &clone
}

func udpAddrEqual(addr, other *net.UDPAddr) bool {
	switch {
	case addr == nil && other == nil:
		return true
	case addr == nil || other == nil:
		return false
	}

	return addr.Port == other.Port && addr.Zone == other.Zone && addr.IP.Equal(other.IP)
}

func udpAddrString(addr *net.UDPAddr) string {
	if addr == nil {
		return ""
	}

	return addr.String()
}

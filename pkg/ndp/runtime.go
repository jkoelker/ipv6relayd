package ndp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mdlayher/ndp"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"

	"github.com/jkoelker/ipv6relayd/pkg/netutil"
)

var errReadTimeout = errors.New("ndp: read timeout")

type runtimeEnvironment struct {
	conn        *icmp.PacketConn
	packetConn  *ipv6.PacketConn
	upstream    *net.Interface
	downstreams []*net.Interface
	allMultiOn  []int
	closeOnce   sync.Once
}

func closePacketConnections(conn *icmp.PacketConn, packetConn *ipv6.PacketConn) {
	if packetConn != nil {
		packetConn.Close()
	}

	if conn != nil {
		conn.Close()
	}
}

func (env *runtimeEnvironment) Close() {
	env.closeOnce.Do(func() {
		for _, idx := range env.allMultiOn {
			if link, err := netlink.LinkByIndex(idx); err == nil {
				_ = netlink.LinkSetAllmulticastOff(link) // best-effort
			}
		}

		if env.packetConn != nil {
			_ = env.packetConn.Close()
		}

		if env.conn != nil {
			_ = env.conn.Close()
		}
	})
}

func (s *Service) Run(ctx context.Context) error {
	if !s.tryStart() {
		return ErrServiceAlreadyRunning
	}
	defer s.finishRun()

	env, err := s.initRuntimeEnvironment()
	if err != nil {
		return err
	}
	defer env.Close()
	defer func() {
		s.cleanupHostRoutes()
		s.packetConn.Store(nil)
	}()
	s.packetConn.Store(env.packetConn)

	sniffers := s.startPacketSniffers(env)
	defer func() {
		for _, sn := range sniffers {
			sn.close()
		}
	}()
	cancelSockets := context.AfterFunc(ctx, func() {
		if s.log != nil {
			s.log.Debug("ndp runtime context canceled; closing sockets")
		}
		env.Close()
		for _, sn := range sniffers {
			sn.close()
		}
	})
	defer cancelSockets()

	if err := s.installStaticRoutes(); err != nil {
		s.log.Warn("failed to install static routes", "err", err)
	}
	defer s.cleanupStaticRoutes()

	if err := s.startInterfaceEvents(ctx); err != nil {
		return fmt.Errorf("start interface events: %w", err)
	}
	defer s.stopInterfaceEvents()

	// Flush cached interface state immediately so startup does not depend on netlink bursts.
	s.refreshMonitorState("initial startup", 0, "")

	s.seedTargets(env.upstream, env.downstreams)
	s.startNeighborMonitor(ctx, env.upstream.Index, env.downstreams)

	s.log.Info(
		"ndp relay started",
		"upstream", env.upstream.Name,
		"downstreams", ifaceNames(env.downstreams),
		"mode", s.cfg.Mode,
	)

	return s.eventLoop(ctx, env)
}

func (s *Service) buildPacketConn() (*icmp.PacketConn, *ipv6.PacketConn, error) {
	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return nil, nil, fmt.Errorf("open icmp socket: %w", err)
	}

	packetConn := conn.IPv6PacketConn()
	if packetConn == nil {
		conn.Close()

		return nil, nil, ErrIPv6PacketConn
	}

	if err := packetConn.SetControlMessage(ipv6.FlagInterface|ipv6.FlagDst|ipv6.FlagHopLimit, true); err != nil {
		closePacketConnections(conn, packetConn)

		return nil, nil, fmt.Errorf("enable control messages: %w", err)
	}

	if err := packetConn.SetChecksum(true, icmpChecksumOffset); err != nil {
		s.log.Warn("failed to enable checksum offload; ndp replies may be invalid", "err", err)
	}

	if err := packetConn.SetMulticastLoopback(false); err != nil {
		closePacketConnections(conn, packetConn)

		return nil, nil, fmt.Errorf("disable multicast loopback: %w", err)
	}

	if err := packetConn.SetMulticastHopLimit(multicastHopLimit); err != nil {
		closePacketConnections(conn, packetConn)

		return nil, nil, fmt.Errorf("set hop limit: %w", err)
	}

	return conn, packetConn, nil
}

func (s *Service) initRuntimeEnvironment() (*runtimeEnvironment, error) {
	conn, packetConn, err := s.buildPacketConn()
	if err != nil {
		return nil, err
	}

	upstreamIface, downstreamIfcs, err := s.lookupInterfaces()
	if err != nil {
		closePacketConnections(conn, packetConn)

		return nil, fmt.Errorf("prepare interfaces: %w", err)
	}

	allMultiOn := s.enableAllMulti(upstreamIface, downstreamIfcs)

	return &runtimeEnvironment{
		conn:        conn,
		packetConn:  packetConn,
		upstream:    upstreamIface,
		downstreams: downstreamIfcs,
		allMultiOn:  allMultiOn,
	}, nil
}

func (s *Service) lookupInterfaces() (*net.Interface, []*net.Interface, error) {
	upstreamIface, err := s.ifaces.ByName(s.upstream.IfName)
	if err != nil {
		return nil, nil, fmt.Errorf("lookup upstream interface %s: %w", s.upstream.IfName, err)
	}

	downstreamIfcs := make([]*net.Interface, 0, len(s.downstreams))
	for _, downstream := range s.downstreams {
		ifc, err := s.ifaces.ByName(downstream.IfName)
		if err != nil {
			return nil, nil, fmt.Errorf("lookup downstream interface %s: %w", downstream.IfName, err)
		}

		downstreamIfcs = append(downstreamIfcs, ifc)
	}

	return upstreamIface, downstreamIfcs, nil
}

func (s *Service) enableAllMulti(upstreamIface *net.Interface, downstreamIfcs []*net.Interface) []int {
	allMultiOn := make([]int, 0, len(downstreamIfcs)+1)

	allMultiOn = s.appendAllMulti(allMultiOn, upstreamIface)
	for _, ifc := range downstreamIfcs {
		allMultiOn = s.appendAllMulti(allMultiOn, ifc)
	}

	return allMultiOn
}

func (s *Service) appendAllMulti(allMultiOn []int, ifc *net.Interface) []int {
	err := setAllMulti(ifc, true)
	if err == nil {
		return append(allMultiOn, ifc.Index)
	}

	s.log.Debug("failed to enable all-multicast", "iface", ifc.Name, "err", err)

	return allMultiOn
}

func setAllMulti(ifc *net.Interface, enable bool) error {
	if ifc == nil {
		return ErrNilInterface
	}

	link, err := netlink.LinkByIndex(ifc.Index)
	if err != nil {
		return fmt.Errorf("link by index %d: %w", ifc.Index, err)
	}

	if enable {
		if err := netlink.LinkSetAllmulticastOn(link); err != nil {
			return fmt.Errorf("set allmulticast on %s: %w", ifc.Name, err)
		}

		return nil
	}

	if err := netlink.LinkSetAllmulticastOff(link); err != nil {
		return fmt.Errorf("set allmulticast off %s: %w", ifc.Name, err)
	}

	return nil
}

func (s *Service) eventLoop(ctx context.Context, env *runtimeEnvironment) error {
	buf := make([]byte, readBufferLen)

	for {
		bytesRead, controlMessage, src, err := s.readPacket(ctx, env, buf)
		if err != nil {
			switch {
			case errors.Is(err, errReadTimeout):
				continue
			case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
				return fmt.Errorf("ndp service context done: %w", err)
			default:
				return err
			}
		}

		s.processPacket(env.packetConn, controlMessage, src, buf[:bytesRead])
	}
}

func (s *Service) processPacket(
	pktConn *ipv6.PacketConn,
	controlMessage *ipv6.ControlMessage,
	src net.Addr,
	payload []byte,
) {
	if controlMessage == nil || len(payload) == 0 {
		return
	}

	snapshot, err := s.snapshotInterfaces()
	if err != nil {
		s.log.Warn("unable to refresh upstream interface", "err", err)

		return
	}

	if controlMessage.HopLimit != multicastHopLimit {
		s.log.Debug("drop ndp packet with invalid hop-limit", "hop_limit", controlMessage.HopLimit, "src", src)

		return
	}

	if s.isPacketFromSelf(snapshot, controlMessage, src) {
		return
	}

	s.routePacket(pktConn, snapshot, controlMessage, src, payload)
}

func (s *Service) readPacket(
	ctx context.Context,
	env *runtimeEnvironment,
	buf []byte,
) (int, *ipv6.ControlMessage, net.Addr, error) {
	if err := env.conn.SetReadDeadline(time.Now().Add(readDeadline)); err != nil {
		return 0, nil, nil, fmt.Errorf("set read deadline: %w", err)
	}

	bytesRead, controlMessage, src, err := env.packetConn.ReadFrom(buf)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			select {
			case <-ctx.Done():
				return 0, nil, nil, fmt.Errorf("context done: %w", ctx.Err())
			default:
				return 0, nil, nil, errReadTimeout
			}
		}

		return 0, nil, nil, fmt.Errorf("read icmp6: %w", err)
	}

	return bytesRead, controlMessage, src, nil
}

type interfaceSnapshot struct {
	upstream           *net.Interface
	downstreamByIndex  map[int]*net.Interface
	currentDownstreams []*net.Interface
	selfIPs            map[int]net.IP
}

func (s *Service) snapshotInterfaces() (*interfaceSnapshot, error) {
	upstreamIface, err := s.ifaces.ByName(s.upstream.IfName)
	if err != nil {
		return nil, fmt.Errorf("refresh upstream interface %s: %w", s.upstream.IfName, err)
	}

	downstreamByIndex := make(map[int]*net.Interface, len(s.downstreams))
	currentDownstreams := make([]*net.Interface, 0, len(s.downstreams))

	for _, downstreamCfg := range s.downstreams {
		ifc, err := s.ifaces.ByName(downstreamCfg.IfName)
		if err != nil {
			s.log.Debug("failed to refresh downstream interface", "iface", downstreamCfg.IfName, "err", err)

			continue
		}

		downstreamByIndex[ifc.Index] = ifc
		currentDownstreams = append(currentDownstreams, ifc)
	}

	selfIPs := make(map[int]net.IP, len(downstreamByIndex)+1)
	if ip, err := s.resolveUpstreamLinkLocal(upstreamIface); err == nil {
		selfIPs[upstreamIface.Index] = ip
	}

	for _, ifc := range currentDownstreams {
		cfg := s.downstreamConfigs[ifc.Name]
		if ip, err := s.resolveDownstreamLinkLocal(ifc, cfg); err == nil {
			selfIPs[ifc.Index] = ip
		}
	}

	return &interfaceSnapshot{
		upstream:           upstreamIface,
		downstreamByIndex:  downstreamByIndex,
		currentDownstreams: currentDownstreams,
		selfIPs:            selfIPs,
	}, nil
}

func (s *Service) isPacketFromSelf(
	snapshot *interfaceSnapshot,
	controlMessage *ipv6.ControlMessage,
	src net.Addr,
) bool {
	ipAddr, ok := src.(*net.IPAddr)
	if !ok {
		return false
	}

	ll, exists := snapshot.selfIPs[controlMessage.IfIndex]

	return exists && ll != nil && ipAddr.IP.Equal(ll)
}

func (s *Service) routePacket(
	packetConn *ipv6.PacketConn,
	snapshot *interfaceSnapshot,
	controlMessage *ipv6.ControlMessage,
	src net.Addr,
	payload []byte,
) {
	typ := ipv6.ICMPType(payload[0])
	switch typ {
	case ipv6.ICMPTypeNeighborSolicitation, ipv6.ICMPTypeNeighborAdvertisement:
		msg, err := ndp.ParseMessage(payload)
		if err != nil {
			s.log.Debug("ignore malformed ndp packet", "err", err)

			return
		}

		s.handleNDPMessage(packetConn, snapshot, controlMessage, src, msg)
	case ipv6.ICMPTypeRedirect:
		srcIP := extractSourceIP(src)
		if err := s.handleRedirect(
			packetConn,
			payload,
			controlMessage,
			srcIP,
			snapshot.upstream,
			snapshot.downstreamByIndex,
			snapshot.currentDownstreams,
		); err != nil {
			s.log.Warn("failed forwarding redirect", "err", err)
		}
	default:
		s.log.Debug("skip icmpv6 type", "type", typ, "src", src)
	}
}

func (s *Service) handleNDPMessage(
	packetConn *ipv6.PacketConn,
	snapshot *interfaceSnapshot,
	controlMessage *ipv6.ControlMessage,
	src net.Addr,
	msg ndp.Message,
) {
	switch m := msg.(type) {
	case *ndp.NeighborSolicitation:
		s.handleNeighborSolicitation(packetConn, snapshot, controlMessage, src, m)
	case *ndp.NeighborAdvertisement:
		s.handleNeighborAdvertisement(packetConn, snapshot, controlMessage, src, m)
	default:
		s.log.Debug("skip icmpv6 type", "type", msg.Type(), "src", src)
	}
}

func (s *Service) handleNeighborSolicitation(
	packetConn *ipv6.PacketConn,
	snapshot *interfaceSnapshot,
	controlMessage *ipv6.ControlMessage,
	src net.Addr,
	msg *ndp.NeighborSolicitation,
) {
	if s.log != nil {
		var hopLimit int
		if controlMessage != nil {
			hopLimit = controlMessage.HopLimit
		}
		s.log.Debug("rx NS",
			"ifindex", controlMessage.IfIndex,
			"dst", controlMessage.Dst,
			"src", src,
			"target", addrToIP(msg.TargetAddress),
			"hop_limit", hopLimit)
	}
	if s.handleDownstreamSolicitation(packetConn, snapshot, controlMessage, src, msg) {
		return
	}

	s.handleUpstreamSolicitation(packetConn, snapshot, controlMessage, src, msg)
}

func (s *Service) handleNeighborAdvertisement(
	packetConn *ipv6.PacketConn,
	snapshot *interfaceSnapshot,
	controlMessage *ipv6.ControlMessage,
	src net.Addr,
	msg *ndp.NeighborAdvertisement,
) {
	if s.handleUpstreamAdvertisement(packetConn, snapshot, controlMessage, src, msg) {
		return
	}

	s.handleDownstreamAdvertisement(packetConn, snapshot, controlMessage, src, msg)
}

func (s *Service) handleDownstreamSolicitation(
	packetConn *ipv6.PacketConn,
	snapshot *interfaceSnapshot,
	controlMessage *ipv6.ControlMessage,
	src net.Addr,
	msg *ndp.NeighborSolicitation,
) bool {
	downstream, ok := snapshot.downstreamByIndex[controlMessage.IfIndex]
	if !ok {
		return false
	}

	downstreamCfg := s.downstreamConfigs[downstream.Name]
	if downstreamCfg.Passive {
		return true
	}

	hostIP, drop := parseSolicitationSource(src, downstream.Name, s.log)
	if drop {
		return true
	}

	target := addrToIP(msg.TargetAddress)
	if target != nil {
		s.trackTarget(target, hostIP, downstream, snapshot.upstream, packetConn)
	}

	if err := s.forwardToUpstream(packetConn, snapshot.upstream, msg, controlMessage, src); err != nil {
		s.log.Warn("failed forwarding NS upstream", "err", err)
	}

	return true
}

func (s *Service) handleUpstreamSolicitation(
	packetConn *ipv6.PacketConn,
	snapshot *interfaceSnapshot,
	controlMessage *ipv6.ControlMessage,
	src net.Addr,
	msg *ndp.NeighborSolicitation,
) {
	if !shouldHandleUpstreamSolicitation(controlMessage, snapshot.upstream) {
		return
	}

	if s.isUpstreamSuppressed() {
		return
	}

	isDAD := isDADProbe(extractSourceIP(src))
	if _, drop := parseSolicitationSource(src, snapshot.upstream.Name, s.log); drop {
		return
	}

	target := addrToIP(msg.TargetAddress)
	s.seedTargetsFromUpstreamNS(target, isDAD, snapshot, controlMessage, packetConn)

	if err := s.forwardSolicitationsToAll(
		packetConn,
		msg,
		controlMessage,
		snapshot.upstream,
		snapshot.currentDownstreams,
		src,
	); err != nil {
		s.log.Warn("failed broadcasting NS downstream", "err", err)
	}
}

func shouldHandleUpstreamSolicitation(controlMessage *ipv6.ControlMessage, upstream *net.Interface) bool {
	return controlMessage.IfIndex == upstream.Index
}

func (s *Service) isUpstreamSuppressed() bool {
	return false
}

func isDADProbe(srcIP net.IP) bool {
	return srcIP == nil || srcIP.IsUnspecified()
}

func (s *Service) seedTargetsFromUpstreamNS(
	target net.IP,
	isDAD bool,
	snapshot *interfaceSnapshot,
	controlMessage *ipv6.ControlMessage,
	packetConn *ipv6.PacketConn,
) {
	if isDAD || target == nil {
		return
	}

	s.log.Debug(
		"upstream NS for downstream target",
		"target", target,
		"ifindex", controlMessage.IfIndex,
		"hop_limit", controlMessage.HopLimit,
	)

	for _, downstream := range snapshot.currentDownstreams {
		s.trackTarget(target, nil, downstream, snapshot.upstream, packetConn)
	}
}

func (s *Service) handleUpstreamAdvertisement(
	packetConn *ipv6.PacketConn,
	snapshot *interfaceSnapshot,
	controlMessage *ipv6.ControlMessage,
	src net.Addr,
	msg *ndp.NeighborAdvertisement,
) bool {
	if controlMessage.IfIndex != snapshot.upstream.Index {
		return false
	}

	if ipAddr, ok := src.(*net.IPAddr); ok && !ipAddr.IP.IsLinkLocalUnicast() {
		s.log.Debug("drop NA with non-link-local source", "src", ipAddr)

		return true
	}

	target := addrToIP(msg.TargetAddress)
	if target != nil {
		if dst, ok := s.lookupTargetInterface(target); ok {
			if err := s.forwardAdvertisementToDownstream(packetConn, msg, controlMessage, dst); err != nil {
				s.log.Warn("failed forwarding NA downstream", "iface", dst.Name, "err", err)
			}

			return true
		}
	}

	if err := s.forwardToDownstreams(packetConn, msg, controlMessage, snapshot.currentDownstreams); err != nil {
		s.log.Warn("failed forwarding NA downstream", "err", err)
	}

	return true
}

func (s *Service) handleDownstreamAdvertisement(
	packetConn *ipv6.PacketConn,
	snapshot *interfaceSnapshot,
	controlMessage *ipv6.ControlMessage,
	src net.Addr,
	msg *ndp.NeighborAdvertisement,
) {
	downstream, ok := snapshot.downstreamByIndex[controlMessage.IfIndex]
	if !ok {
		return
	}

	downstreamCfg := s.downstreamConfigs[downstream.Name]
	if downstreamCfg.Passive {
		return
	}

	var hostIP net.IP
	if ipAddr, ok := src.(*net.IPAddr); ok {
		hostIP = netutil.CloneAddr(ipAddr.IP)
	}

	if target := addrToIP(msg.TargetAddress); target != nil {
		s.trackTarget(target, hostIP, downstream, snapshot.upstream, packetConn)
	}

	if err := s.forwardAdvertisementToUpstream(packetConn, msg, controlMessage, snapshot.upstream); err != nil {
		s.log.Warn("failed forwarding NA upstream", "err", err)
	}
}

func parseSolicitationSource(src net.Addr, ifaceName string, logger *slog.Logger) (net.IP, bool) {
	if src == nil {
		return nil, false
	}

	ipAddr, ok := src.(*net.IPAddr)
	if !ok {
		return nil, false
	}

	switch {
	case ipAddr.IP.IsUnspecified():
		if logger != nil {
			logger.Debug("detected DAD probe; forwarding without tracking", "iface", ifaceName)
		}

		return nil, false
	case !ipAddr.IP.IsLinkLocalUnicast():
		if logger != nil {
			logger.Debug("drop NS with non-link-local source", "src", ipAddr)
		}

		return nil, true
	default:
		return netutil.CloneAddr(ipAddr.IP), false
	}
}

package dhcpv6

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/ipv6"
)

var errReadTimeout = errors.New("dhcpv6: read timeout")

type runtimeEnvironment struct {
	conn        *net.UDPConn
	pktConn     *ipv6.PacketConn
	upstream    *net.Interface
	downstreams []*net.Interface
	closeOnce   sync.Once
}

func (env *runtimeEnvironment) Close() {
	env.closeOnce.Do(func() {
		if env.pktConn != nil {
			_ = env.pktConn.Close()
		}

		if env.conn != nil {
			_ = env.conn.Close()
		}
	})
}

func (s *Service) Run(ctx context.Context) error {
	if !s.tryStart() {
		return ErrServiceAlreadyStarted
	}
	defer s.finishRun()

	env, err := s.initRuntimeEnvironment()
	if err != nil {
		return err
	}
	defer env.Close()
	cancelSockets := context.AfterFunc(ctx, func() {
		if s.log != nil {
			s.log.Debug("dhcpv6 runtime context canceled; closing sockets")
		}
		env.Close()
	})
	defer cancelSockets()

	if err := s.startInterfaceEvents(ctx, env.pktConn); err != nil {
		return fmt.Errorf("start interface events: %w", err)
	}
	defer s.stopInterfaceEvents()

	// Prime multicast memberships and upstream state before relying on event-driven refreshes.
	s.refreshInterfaceState(env.pktConn, "initial startup")

	upstream := s.currentUpstream()
	upstreamStr := ""
	if upstream != nil {
		upstreamStr = upstream.String()
	}

	s.log.Info(
		"dhcpv6 relay started",
		"upstream", env.upstream.Name,
		"downstreams", ifaceNames(env.downstreams),
		"upstream", upstreamStr,
	)

	return s.eventLoop(ctx, env)
}

func (s *Service) initRuntimeEnvironment() (*runtimeEnvironment, error) {
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: serverPort})
	if err != nil {
		return nil, fmt.Errorf("listen udp6: %w", err)
	}

	pktConn := ipv6.NewPacketConn(conn)
	if err := pktConn.SetControlMessage(ipv6.FlagInterface|ipv6.FlagHopLimit|ipv6.FlagDst, true); err != nil {
		conn.Close()

		return nil, fmt.Errorf("control message: %w", err)
	}

	if err := pktConn.SetMulticastLoopback(false); err != nil {
		conn.Close()

		return nil, fmt.Errorf("disable loopback: %w", err)
	}

	upstreamIface, downstreamIfcs, err := s.prepareInterfaces()
	if err != nil {
		pktConn.Close()
		conn.Close()

		return nil, err
	}

	if _, err := s.joinMulticastGroups(pktConn, upstreamIface, downstreamIfcs); err != nil {
		pktConn.Close()
		conn.Close()

		return nil, err
	}

	return &runtimeEnvironment{
		conn:        conn,
		pktConn:     pktConn,
		upstream:    upstreamIface,
		downstreams: downstreamIfcs,
	}, nil
}

func (s *Service) prepareInterfaces() (*net.Interface, []*net.Interface, error) {
	upstreamIface, err := s.ifaces.ByName(s.upstreamIface.IfName)
	if err != nil {
		return nil, nil, fmt.Errorf("lookup upstream interface %s: %w", s.upstreamIface.IfName, err)
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

func (s *Service) joinMulticastGroups(
	pktConn *ipv6.PacketConn,
	upstreamIface *net.Interface,
	downstreamIfcs []*net.Interface,
) (net.IP, error) {
	mcastIP := net.ParseIP(mcastAddr)
	if mcastIP == nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidMulticastConst, mcastAddr)
	}

	if err := pktConn.LeaveGroup(
		upstreamIface,
		&net.UDPAddr{IP: mcastIP},
	); err != nil && !shouldIgnoreMulticastLeave(err) {
		s.log.Debug("failed to leave upstream multicast group", "err", err)
	}

	if err := pktConn.JoinGroup(upstreamIface, &net.UDPAddr{IP: mcastIP}); err != nil {
		return nil, fmt.Errorf("join multicast upstream: %w", err)
	}

	for _, ifc := range downstreamIfcs {
		if err := pktConn.LeaveGroup(ifc, &net.UDPAddr{IP: mcastIP}); err != nil && !shouldIgnoreMulticastLeave(err) {
			s.log.Debug("failed to leave downstream multicast group", "iface", ifc.Name, "err", err)
		}

		if err := pktConn.JoinGroup(ifc, &net.UDPAddr{IP: mcastIP}); err != nil {
			return nil, fmt.Errorf("join multicast downstream %s: %w", ifc.Name, err)
		}
	}

	s.multicastIP = mcastIP

	return mcastIP, nil
}

func (s *Service) eventLoop(ctx context.Context, env *runtimeEnvironment) error {
	buf := make([]byte, readBufferSize)

	for {
		payload, controlMsg, src, err := s.readPacket(ctx, env, buf)
		if err != nil {
			if errors.Is(err, errReadTimeout) {
				continue
			}

			return err
		}

		s.routePacket(ctx, env.pktConn, controlMsg, src, payload)
	}
}

func (s *Service) routePacket(
	ctx context.Context,
	pktConn *ipv6.PacketConn,
	controlMsg *ipv6.ControlMessage,
	src net.Addr,
	payload []byte,
) {
	if controlMsg == nil {
		s.log.Debug("receive packet without control message")

		return
	}

	upstreamIface, err := s.ifaces.ByName(s.upstreamIface.IfName)
	if err != nil {
		s.log.Warn("failed to refresh upstream interface", "err", err)

		return
	}

	if controlMsg.IfIndex == upstreamIface.Index {
		if err := s.handleUpstream(ctx, pktConn, payload); err != nil {
			s.log.Warn("failed to deliver response downstream", "err", err)
		}

		return
	}

	downstreamIface, downstreamCfg, err := s.downstreamInterfaceByIndex(controlMsg.IfIndex)
	if err != nil {
		if errors.Is(err, ErrInterfaceNotManaged) {
			s.log.Debug("packet from interface not tracked", "ifindex", controlMsg.IfIndex)

			return
		}

		s.log.Warn("failed to resolve downstream interface", "ifindex", controlMsg.IfIndex, "err", err)

		return
	}

	if err := s.handleDownstream(ctx, pktConn, downstreamIface, downstreamCfg, src, payload); err != nil {
		s.log.Warn("failed to forward client message", "iface", downstreamIface.Name, "err", err)
	}
}

func (s *Service) readPacket(
	ctx context.Context,
	env *runtimeEnvironment,
	buf []byte,
) ([]byte, *ipv6.ControlMessage, net.Addr, error) {
	if err := env.conn.SetReadDeadline(time.Now().Add(readDeadlineInterval)); err != nil {
		return nil, nil, nil, fmt.Errorf("set read deadline: %w", err)
	}

	bytesRead, controlMsg, src, err := env.pktConn.ReadFrom(buf)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			if ctx.Err() != nil {
				return nil, nil, nil, fmt.Errorf("context canceled during read: %w", ctx.Err())
			}

			return nil, nil, nil, errReadTimeout
		}

		return nil, nil, nil, fmt.Errorf("read udp6: %w", err)
	}

	payload := make([]byte, bytesRead)
	copy(payload, buf[:bytesRead])

	return payload, controlMsg, src, nil
}

func ifaceNames(ifcs []*net.Interface) []string {
	names := make([]string, 0, len(ifcs))
	for _, ifc := range ifcs {
		names = append(names, ifc.Name)
	}

	return names
}

func (s *Service) startInterfaceEvents(ctx context.Context, pktConn *ipv6.PacketConn) error {
	if s.ifaceEvents == nil {
		return ErrInterfaceEventsNeeded
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
				s.refreshInterfaceState(pktConn, ev.Reason)
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

func (s *Service) refreshInterfaceState(pktConn *ipv6.PacketConn, reason string) {
	s.ifaces.Flush()

	if err := s.refreshMulticast(pktConn); err != nil {
		s.log.Warn("failed to refresh DHCPv6 multicast", "reason", reason, "err", err)
	}

	if err := s.refreshUpstream(reason); err != nil {
		s.log.Warn("failed to refresh dhcpv6 upstream", "reason", reason, "err", err)
	}
}

func (s *Service) refreshMulticast(pktConn *ipv6.PacketConn) error {
	mcastIP, err := s.resolveMulticastIP()
	if err != nil {
		return fmt.Errorf("resolve multicast ip: %w", err)
	}

	upstreamIface, err := s.ifaces.ByName(s.upstreamIface.IfName)
	if err != nil {
		return fmt.Errorf("lookup upstream interface: %w", err)
	}

	if err := s.joinMulticastGroup(pktConn, upstreamIface, mcastIP, "rejoin upstream multicast"); err != nil {
		return fmt.Errorf("rejoin upstream multicast: %w", err)
	}

	return s.refreshDownstreamMulticast(pktConn, mcastIP)
}

func (s *Service) resolveMulticastIP() (net.IP, error) {
	if s.multicastIP != nil {
		return s.multicastIP, nil
	}

	multicastIP := net.ParseIP(mcastAddr)
	if multicastIP == nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidMulticastConst, mcastAddr)
	}

	return multicastIP, nil
}

func (s *Service) joinMulticastGroup(pc *ipv6.PacketConn, ifc *net.Interface, mcastIP net.IP, errPrefix string) error {
	if err := pc.JoinGroup(ifc, &net.UDPAddr{IP: mcastIP}); err != nil {
		if isAddressInUseError(err) {
			return nil
		}

		return fmt.Errorf("%s: %w", errPrefix, err)
	}

	return nil
}

func (s *Service) refreshDownstreamMulticast(pktConn *ipv6.PacketConn, mcastIP net.IP) error {
	var firstErr error

	for _, downstream := range s.downstreams {
		ifc, err := s.ifaces.ByName(downstream.IfName)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("lookup downstream %s: %w", downstream.IfName, err)
			}

			continue
		}

		errPrefix := fmt.Sprintf("rejoin downstream %s multicast", ifc.Name)
		if err := s.joinMulticastGroup(pktConn, ifc, mcastIP, errPrefix); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

func shouldIgnoreMulticastLeave(err error) bool {
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		return false
	}

	var errno syscall.Errno
	if !errors.As(opErr.Err, &errno) {
		return false
	}

	return errno == syscall.EADDRNOTAVAIL || errno == syscall.ENODEV
}

func isAddressInUseError(err error) bool {
	// The join socket errors can surface as *net.OpError wrapping syscall.EADDRINUSE
	// or directly as *os.SyscallError when the kernel reports EADDRINUSE from
	// IPV6_JOIN_GROUP. Use errors.Is so both shapes are handled.
	return errors.Is(err, syscall.EADDRINUSE)
}

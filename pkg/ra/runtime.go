package ra

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

type relayRuntime struct {
	service        *Service
	conn           *icmp.PacketConn
	packetConn     *ipv6.PacketConn
	upstreamIfc    *net.Interface
	downstreamIfcs []*net.Interface
	readBuf        []byte
	closeOnce      sync.Once
}

func newRelayRuntime(service *Service) (*relayRuntime, error) {
	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return nil, fmt.Errorf("open icmpv6 socket: %w", err)
	}

	runtime := &relayRuntime{
		service: service,
		conn:    conn,
	}

	if err := runtime.initPacketConn(); err != nil {
		runtime.Close()

		return nil, err
	}

	if err := runtime.resolveInterfaces(); err != nil {
		runtime.Close()

		return nil, err
	}

	if err := runtime.joinMulticastGroups(); err != nil {
		runtime.Close()

		return nil, err
	}

	runtime.readBuf = make([]byte, readBufferSize)

	return runtime, nil
}

func (r *relayRuntime) Close() {
	r.closeOnce.Do(func() {
		if r.packetConn != nil {
			_ = r.packetConn.Close()
		}

		if r.conn != nil {
			_ = r.conn.Close()
		}
	})
}

func (r *relayRuntime) closeOnContext(ctx context.Context) {
	go func() {
		<-ctx.Done()
		r.service.log.Debug("ra runtime context canceled; closing sockets")
		r.Close()
	}()
}

func (r *relayRuntime) initPacketConn() error {
	ipv6Conn := r.conn.IPv6PacketConn()
	if ipv6Conn == nil {
		return ErrIPv6PacketConn
	}

	if err := ipv6Conn.SetControlMessage(
		ipv6.FlagInterface|ipv6.FlagDst|ipv6.FlagHopLimit|ipv6.FlagSrc,
		true,
	); err != nil {
		return fmt.Errorf("configure control messages: %w", err)
	}

	if err := ipv6Conn.SetChecksum(true, ipv6ChecksumOffset); err != nil {
		return fmt.Errorf("enable ipv6 checksum offload: %w", err)
	}

	if err := ipv6Conn.SetMulticastHopLimit(multicastHopLimit); err != nil {
		return fmt.Errorf("set mcast hop limit: %w", err)
	}

	if err := ipv6Conn.SetMulticastLoopback(false); err != nil {
		return fmt.Errorf("set multicast loopback: %w", err)
	}

	r.packetConn = ipv6Conn

	return nil
}

func (r *relayRuntime) resolveInterfaces() error {
	upstreamIfc, err := r.service.ifaces.ByName(r.service.upstream.IfName)
	if err != nil {
		return fmt.Errorf("lookup upstream %s: %w", r.service.upstream.IfName, err)
	}

	downstreamIfcs := make([]*net.Interface, 0, len(r.service.downstreams))
	for _, downstreamCfg := range r.service.downstreams {
		ifc, err := r.service.ifaces.ByName(downstreamCfg.IfName)
		if err != nil {
			return fmt.Errorf("lookup downstream %s: %w", downstreamCfg.IfName, err)
		}

		downstreamIfcs = append(downstreamIfcs, ifc)
	}

	r.upstreamIfc = upstreamIfc
	r.downstreamIfcs = downstreamIfcs

	return nil
}

func (r *relayRuntime) joinMulticastGroups() error {
	if err := joinGroups(r.packetConn, r.upstreamIfc, []string{allNodesMulticast, allRoutersMulticast}); err != nil {
		return fmt.Errorf("join upstream groups: %w", err)
	}

	for _, downstream := range r.downstreamIfcs {
		if err := joinGroups(r.packetConn, downstream, []string{allNodesMulticast, allRoutersMulticast}); err != nil {
			return fmt.Errorf("join downstream groups: %w", err)
		}
	}

	return nil
}

func (r *relayRuntime) run(ctx context.Context) error {
	r.service.log.Info("router advertisement relay started",
		"upstream", r.upstreamIfc.Name,
		"downstreams", interfaceNames(r.downstreamIfcs))

	for {
		readBytes, ctrlMsg, src, err := r.readMessage(ctx)
		if err != nil {
			return err
		}

		if ctrlMsg == nil {
			continue
		}

		if err := r.dispatchMessage(ctx, r.readBuf[:readBytes], ctrlMsg, src); err != nil {
			return err
		}
	}
}

func (r *relayRuntime) readMessage(
	ctx context.Context,
) (int, *ipv6.ControlMessage, *net.IPAddr, error) {
	if err := r.conn.SetReadDeadline(time.Now().Add(readDeadline)); err != nil {
		return 0, nil, nil, fmt.Errorf("set read deadline: %w", err)
	}

	readBytes, ctrlMsg, src, err := r.packetConn.ReadFrom(r.readBuf)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			select {
			case <-ctx.Done():
				return 0, nil, nil, fmt.Errorf("context canceled while reading icmpv6: %w", ctx.Err())
			default:
				return 0, nil, nil, nil
			}
		}

		return 0, nil, nil, fmt.Errorf("read icmpv6: %w", err)
	}

	ipAddr, _ := src.(*net.IPAddr)

	return readBytes, ctrlMsg, ipAddr, nil
}

func (r *relayRuntime) dispatchMessage(
	ctx context.Context,
	payload []byte,
	ctrlMsg *ipv6.ControlMessage,
	src *net.IPAddr,
) error {
	return r.service.DispatchMessage(ctx, r.packetConn, r.upstreamIfc, payload, ctrlMsg, src)
}

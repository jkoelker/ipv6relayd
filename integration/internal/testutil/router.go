//go:build linux

package testutil

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netns"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

const (
	routerHopLimit     = 255
	raPayloadLen       = 16
	raOtherConfigFlag  = 0x40
	raManagedFlag      = 0x80
	raSendInterval     = 2 * time.Second
	raReadBufferSize   = 1500
	icmpChecksumOffset = 2
	raReadDeadline     = 2 * time.Second
	raMinPayloadLength = 6
	raFlagOffset       = 1 // within RA body (after ICMP header)
)

var (
	errIPv6PacketConnMissing = errors.New("ipv6 packet connection missing")
	errUnexpectedSourceType  = errors.New("unexpected source type")
)

type RACapture struct {
	Payload  []byte
	Source   *net.IPAddr
	HopLimit int
	Received time.Time
}

type routerSession struct {
	conn       *icmp.PacketConn
	packetConn *ipv6.PacketConn
	dst        *net.IPAddr
	payload    []byte
	ifName     string
}

func newRouterSession(iface string) (*routerSession, error) {
	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return nil, fmt.Errorf("listen icmpv6: %w", err)
	}

	packetConn := conn.IPv6PacketConn()
	if packetConn == nil {
		conn.Close()

		return nil, errIPv6PacketConnMissing
	}

	_ = packetConn.SetChecksum(true, icmpChecksumOffset)

	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		conn.Close()

		return nil, fmt.Errorf("interface lookup: %w", err)
	}

	if err := packetConn.SetMulticastInterface(ifc); err != nil {
		conn.Close()

		return nil, fmt.Errorf("set multicast iface: %w", err)
	}
	if err := packetConn.SetMulticastHopLimit(routerHopLimit); err != nil {
		conn.Close()

		return nil, fmt.Errorf("set hop limit: %w", err)
	}
	_ = packetConn.SetControlMessage(ipv6.FlagInterface|ipv6.FlagSrc|ipv6.FlagHopLimit, true)

	dst := &net.IPAddr{
		IP: net.ParseIP("ff02::1"),
		Zone: func() string {
			if ifc != nil {
				return ifc.Name
			}

			return ""
		}(),
	}

	payload := make([]byte, raPayloadLen)
	// Populate RA body: Cur Hop Limit + Flags; rest zero for test purposes.
	payload[0] = 64 // Cur Hop Limit

	return &routerSession{
		conn:       conn,
		packetConn: packetConn,
		dst:        dst,
		payload:    payload,
		ifName:     iface,
	}, nil
}

func (r *routerSession) Close() error {
	if err := r.conn.Close(); err != nil {
		return fmt.Errorf("close router session: %w", err)
	}

	return nil
}

func (r *routerSession) sendLoop(ctx context.Context) error {
	ticker := time.NewTicker(raSendInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("router session canceled: %w", err)
			}

			return nil
		case <-ticker.C:
			msg := icmp.Message{
				Type: ipv6.ICMPTypeRouterAdvertisement,
				Body: &icmp.RawBody{Data: r.payload},
			}
			raw, err := msg.Marshal(nil)
			if err != nil {
				return fmt.Errorf("marshal router advertisement: %w", err)
			}
			if _, err := r.packetConn.WriteTo(
				raw,
				&ipv6.ControlMessage{HopLimit: routerHopLimit, IfIndex: 0},
				r.dst,
			); err != nil {
				return fmt.Errorf("send router advertisement: %w", err)
			}
		}
	}
}

func RunUpstreamRouter(ctx context.Context, iface string) error {
	session, err := newRouterSession(iface)
	if err != nil {
		return fmt.Errorf("new router session: %w", err)
	}
	defer session.Close()

	return session.sendLoop(ctx)
}

func waitForRouterAdvertisement(ctx context.Context, ns netns.NsHandle) (*RACapture, error) {
	var rawConn *icmp.PacketConn
	if err := WithNetNS(ns, func() error {
		c, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
		if err != nil {
			return fmt.Errorf("listen icmpv6: %w", err)
		}
		rawConn = c

		return nil
	}); err != nil {
		return nil, fmt.Errorf("setup RA listener: %w", err)
	}
	defer func() {
		_ = rawConn.Close()
	}()

	if err := rawConn.IPv6PacketConn().SetControlMessage(ipv6.FlagInterface|ipv6.FlagHopLimit, true); err != nil {
		return nil, fmt.Errorf("enable control message: %w", err)
	}

	readBuffer := make([]byte, raReadBufferSize)
	for {
		capture, keepWaiting, err := readRouterAdvertisementOnce(ctx, rawConn, readBuffer)
		if err != nil {
			return nil, err
		}

		if keepWaiting {
			continue
		}

		return capture, nil
	}
}

func readRouterAdvertisementOnce(ctx context.Context, rawConn *icmp.PacketConn, buf []byte) (*RACapture, bool, error) {
	if err := rawConn.SetReadDeadline(time.Now().Add(raReadDeadline)); err != nil {
		return nil, false, fmt.Errorf("set read deadline: %w", err)
	}

	readLen, control, src, err := rawConn.IPv6PacketConn().ReadFrom(buf)
	if err != nil {
		if IsTimeoutErr(err) {
			if ctx.Err() != nil {
				return nil, false, fmt.Errorf("context done while waiting for router advertisement: %w", ctx.Err())
			}

			return nil, true, nil
		}

		return nil, false, fmt.Errorf("read router advertisement: %w", err)
	}

	msg, err := icmp.ParseMessage(ipv6.ICMPTypeRouterAdvertisement.Protocol(), buf[:readLen])
	if err != nil {
		return nil, false, fmt.Errorf("parse router advertisement: %w", err)
	}

	if msg.Type != ipv6.ICMPTypeRouterAdvertisement {
		return nil, true, nil
	}

	if control == nil {
		return nil, true, nil
	}

	body, ok := msg.Body.(*icmp.RawBody)
	if !ok {
		return nil, true, nil
	}

	ipSrc, ok := src.(*net.IPAddr)
	if !ok {
		return nil, false, fmt.Errorf("%w: %T", errUnexpectedSourceType, src)
	}

	return &RACapture{
		Payload:  body.Data,
		Source:   ipSrc,
		HopLimit: control.HopLimit,
		Received: time.Now(),
	}, false, nil
}

func MustRouterAdvertisement(ctx context.Context, t *testing.T, ns netns.NsHandle) *RACapture {
	t.Helper()
	advCapture, err := waitForRouterAdvertisement(ctx, ns)
	require.NoError(t, err, "router advertisement not received")
	require.NotNil(t, advCapture, "router advertisement capture missing payload")

	return advCapture
}

func ValidateRouterAdvertisement(t *testing.T, raCap *RACapture, expectManaged, expectOther bool) {
	t.Helper()
	require.Equal(t, routerHopLimit, raCap.HopLimit, "unexpected RA hop limit")
	require.NotNil(t, raCap.Source, "router advertisement source missing")
	assert.True(t, raCap.Source.IP.IsLinkLocalUnicast(), "router advertisement source not link-local: %+v", raCap.Source)
	require.GreaterOrEqual(t, len(raCap.Payload), raMinPayloadLength, "router advertisement payload too short")
	if expectManaged {
		assert.NotZero(t, raCap.Payload[raFlagOffset]&raManagedFlag, "managed flag should be set")
	} else {
		assert.Zero(t, raCap.Payload[raFlagOffset]&raManagedFlag, "managed flag should be clear")
	}

	if expectOther {
		assert.NotZero(t, raCap.Payload[raFlagOffset]&raOtherConfigFlag, "other-config flag should be set")
	} else {
		assert.Zero(t, raCap.Payload[raFlagOffset]&raOtherConfigFlag, "other-config flag should be clear")
	}
}

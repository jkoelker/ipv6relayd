//go:build linux

package testutil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netns"
	"golang.org/x/net/ipv6"
)

const (
	DHCPServerPort       = 547
	DHCPClientPort       = 546
	DHCPBufferSize       = 4096
	DHCPReadDeadline     = 2 * time.Second
	DHCPSolicitMulticast = "ff02::1:2"
)

var ErrSkipPacket = errors.New("skip dhcpv6 packet")

func RunUpstreamDHCPv6(ctx context.Context, t *testing.T, iface string) error {
	t.Helper()

	return RunUpstreamDHCPv6WithValidator(ctx, t, iface, nil)
}

func RunUpstreamDHCPv6WithValidator(
	ctx context.Context,
	t *testing.T,
	iface string,
	validate func(*dhcpv6.RelayMessage) error,
) error {
	t.Helper()

	addr := &net.UDPAddr{IP: net.IPv6unspecified, Port: DHCPServerPort}

	ifc, _ := net.InterfaceByName(iface)
	if addrs, _ := ifc.Addrs(); len(addrs) > 0 {
		t.Logf("upstream: iface %s addrs: %v", iface, addrs)
	}

	conn, err := net.ListenUDP("udp6", addr)
	if err != nil {
		return fmt.Errorf("listen udp6: %w", err)
	}
	defer conn.Close()

	buffer := make([]byte, DHCPBufferSize)

	for {
		relay, remoteAddr, err := ReadRelayForward(ctx, t, conn, iface, buffer)
		if err != nil {
			if errors.Is(err, ErrSkipPacket) {
				continue
			}

			return err
		}

		if err := handleRelayForwardReply(t, conn, relay, remoteAddr, validate); err != nil {
			if errors.Is(err, ErrSkipPacket) {
				continue
			}

			return err
		}
	}
}

func handleRelayForwardReply(
	t *testing.T,
	conn *net.UDPConn,
	relay *dhcpv6.RelayMessage,
	remoteAddr *net.UDPAddr,
	validate func(*dhcpv6.RelayMessage) error,
) error {
	t.Helper()

	if validate != nil {
		if err := validate(relay); err != nil {
			return fmt.Errorf("relay-forward validation failed: %w", err)
		}
	}

	t.Logf("upstream: got relay-forward %dB from %s (zone=%s)", len(relay.ToBytes()), remoteAddr, remoteAddr.Zone)
	reply, err := BuildRelayReply(relay)
	if err != nil {
		return err
	}

	body := reply.Options.RelayMessage()
	t.Logf("upstream: reply %s -> %s (iface=%s) inner=%T", remoteAddr, relay.PeerAddr, remoteAddr.Zone, body)

	if _, err := conn.WriteToUDP(reply.ToBytes(), remoteAddr); err != nil {
		return fmt.Errorf("send relay reply: %w", err)
	}

	return nil
}

func ReadRelayForward(
	ctx context.Context,
	t *testing.T,
	conn *net.UDPConn,
	iface string,
	buffer []byte,
) (*dhcpv6.RelayMessage, *net.UDPAddr, error) {
	t.Helper()

	if err := conn.SetReadDeadline(time.Now().Add(DHCPReadDeadline)); err != nil {
		return nil, nil, fmt.Errorf("set read deadline: %w", err)
	}

	bytesRead, remoteAddr, err := conn.ReadFromUDP(buffer)
	if err != nil {
		if IsTimeoutErr(err) {
			if ctx.Err() != nil {
				return nil, nil, fmt.Errorf("context done while waiting for upstream packet: %w", ctx.Err())
			}

			return nil, nil, ErrSkipPacket
		}

		return nil, nil, fmt.Errorf("read upstream: %w", err)
	}

	t.Logf("upstream: raw %dB from %s (zone=%s)", bytesRead, remoteAddr, remoteAddr.Zone)

	packet, err := dhcpv6.FromBytes(buffer[:bytesRead])
	if err != nil {
		t.Logf("upstream: parse error %v", err)

		return nil, nil, ErrSkipPacket
	}

	relay, ok := packet.(*dhcpv6.RelayMessage)
	if !ok || relay.MessageType != dhcpv6.MessageTypeRelayForward {
		return nil, nil, ErrSkipPacket
	}

	if remoteAddr.Zone == "" {
		remoteAddr.Zone = iface
	}

	return relay, remoteAddr, nil
}

func BuildRelayReply(relay *dhcpv6.RelayMessage) (*dhcpv6.RelayMessage, error) {
	inner := relay.Options.RelayMessage()
	if inner == nil {
		return nil, ErrSkipPacket
	}

	msg, ok := inner.(*dhcpv6.Message)
	if !ok {
		return nil, ErrSkipPacket
	}

	reply := &dhcpv6.Message{
		MessageType:   dhcpv6.MessageTypeReply,
		TransactionID: msg.TransactionID,
	}

	if cid := msg.Options.GetOne(dhcpv6.OptionClientID); cid != nil {
		reply.Options.Add(cid)
	}

	reply.Options.Add(dhcpv6.OptDNS(net.ParseIP("2001:db8:53::53")))

	out, err := dhcpv6.EncapsulateRelay(reply, dhcpv6.MessageTypeRelayReply, relay.LinkAddr, relay.PeerAddr)
	if err != nil {
		return nil, fmt.Errorf("encapsulate relay reply: %w", err)
	}

	if iid := relay.Options.InterfaceID(); len(iid) > 0 {
		out.Options.Add(dhcpv6.OptInterfaceID(iid))
	}

	return out, nil
}

func SolicitDHCPv6(ctx context.Context, t *testing.T, ns netns.NsHandle, iface string) (*dhcpv6.Message, error) {
	t.Helper()

	var result *dhcpv6.Message

	err := WithNetNS(ns, func() error {
		conn, packetConn, hwAddr, err := newDHCPv6ClientConn(iface)
		if err != nil {
			return err
		}
		defer conn.Close()
		defer packetConn.Close()

		if err := sendSolicit(t, conn, hwAddr, iface); err != nil {
			return err
		}

		msg, err := waitForDHCPv6ReplyWithRetry(ctx, conn, func() error {
			return sendSolicit(t, conn, hwAddr, iface)
		})
		if err != nil {
			return err
		}

		result = msg

		return nil
	})

	return result, err
}

func newDHCPv6ClientConn(iface string) (*net.UDPConn, *ipv6.PacketConn, net.HardwareAddr, error) {
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: DHCPClientPort, Zone: iface})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("listen udp6 client: %w", err)
	}

	packetConn := ipv6.NewPacketConn(conn)

	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		packetConn.Close()
		conn.Close()

		return nil, nil, nil, fmt.Errorf("interface lookup: %w", err)
	}

	if err := packetConn.JoinGroup(ifc, &net.UDPAddr{IP: net.ParseIP(DHCPSolicitMulticast)}); err != nil {
		packetConn.Close()
		conn.Close()

		return nil, nil, nil, fmt.Errorf("join dhcp mcast: %w", err)
	}

	hwAddr := ifc.HardwareAddr
	if len(hwAddr) == 0 {
		hwAddr = net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	}

	return conn, packetConn, hwAddr, nil
}

func sendSolicit(t *testing.T, conn *net.UDPConn, hwAddr net.HardwareAddr, iface string) error {
	t.Helper()

	solicit, err := dhcpv6.NewSolicit(hwAddr)
	if err != nil {
		return fmt.Errorf("new solicit: %w", err)
	}

	dst := &net.UDPAddr{IP: net.ParseIP(DHCPSolicitMulticast), Zone: iface, Port: DHCPServerPort}

	t.Logf("client: send SOLICIT from %s to %s", conn.LocalAddr(), dst)
	if _, err := conn.WriteToUDP(solicit.ToBytes(), dst); err != nil {
		return fmt.Errorf("send solicit: %w", err)
	}

	return nil
}

func waitForDHCPv6ReplyWithRetry(ctx context.Context, conn *net.UDPConn, resend func() error) (*dhcpv6.Message, error) {
	buffer := make([]byte, DHCPBufferSize)

	for {
		if err := conn.SetReadDeadline(time.Now().Add(DHCPReadDeadline)); err != nil {
			return nil, fmt.Errorf("set read deadline: %w", err)
		}

		bytesRead, _, err := conn.ReadFromUDP(buffer)
		if err == nil {
			pkt, err := dhcpv6.FromBytes(buffer[:bytesRead])
			if err != nil {
				continue
			}

			msg, ok := pkt.(*dhcpv6.Message)
			if !ok {
				continue
			}

			return msg, nil
		}

		if !IsTimeoutErr(err) {
			return nil, fmt.Errorf("read reply: %w", err)
		}

		if ctx.Err() != nil {
			return nil, fmt.Errorf("context done waiting for dhcp reply: %w", ctx.Err())
		}

		if resend != nil {
			if err := resend(); err != nil {
				return nil, fmt.Errorf("resend solicit: %w", err)
			}
		}
	}
}

func MustDHCPv6Reply(ctx context.Context, t *testing.T, ns netns.NsHandle, iface string) *dhcpv6.Message {
	t.Helper()
	msg, err := SolicitDHCPv6(ctx, t, ns, iface)
	require.NoError(t, err, "dhcpv6 flow failed")

	return msg
}

func ValidateDHCPv6Reply(t *testing.T, reply *dhcpv6.Message) {
	t.Helper()
	require.Equal(t, dhcpv6.MessageTypeReply, reply.Type(), "unexpected DHCPv6 message type")

	dns := reply.Options.GetOne(dhcpv6.OptionDNSRecursiveNameServer)
	require.NotNil(t, dns, "expected DNS option in reply")

	wantedDNS := net.ParseIP("2001:db8:53::53").To16()
	require.NotNil(t, wantedDNS, "wanted DNS parse failed")
	assert.True(
		t,
		bytes.Contains(dns.ToBytes(), wantedDNS),
		"dns override mismatch; want 2001:db8:53::53, opt=%x",
		dns.ToBytes(),
	)
}

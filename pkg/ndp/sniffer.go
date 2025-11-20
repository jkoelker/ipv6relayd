package ndp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"sync"

	"github.com/mdlayher/packet"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	ethernetHeaderLen = 14
	ipv6HeaderLen     = 40
	icmpHeaderMinLen  = 8
	maxCaptureLen     = 256
	snifferBufLen     = 2048

	ethernetAddrLen = 6
	ethHeaderNext   = 6 // offset of NextHeader field inside IPv6 header when preceded by Ethernet

	bpfNextHeaderOffset = ethernetHeaderLen + ethHeaderNext
	bpfICMPTypeOffset   = ethernetHeaderLen + ipv6HeaderLen

	icmpv6NextHeader = 58
	icmpv6NS         = 135
	icmpv6NA         = 136

	bpfDropJump = 4
	bpfNAJump   = 1
	bpfNSJump   = 2
)

var errIfindexTooLarge = errors.New("ifindex exceeds int32")

// packetSniffer taps ICMPv6 packets directly from the link layer so we can
// observe Neighbor Discovery traffic even when the kernel hasn't joined the
// relevant solicited-node multicast groups yet.
type packetSniffer struct {
	conn      *packet.Conn
	ifindex   int
	ifname    string
	closeOnce sync.Once
}

func (s *packetSniffer) close() {
	s.closeOnce.Do(func() {
		if s.conn != nil {
			_ = s.conn.Close() // best-effort
		}
	})
}

func (svc *Service) startPacketSniffers(env *runtimeEnvironment) []*packetSniffer {
	sniffers := make([]*packetSniffer, 0, len(env.downstreams)+1)

	add := func(ifc *net.Interface) {
		sniffer, err := openPacketSniffer(ifc)
		if err != nil {
			svc.log.Warn("failed to start ndp sniffer", "iface", ifc.Name, "err", err)

			return
		}

		sniffers = append(sniffers, sniffer)
		go svc.sniffLoop(sniffer, env.packetConn)
	}

	add(env.upstream)
	for _, downstream := range env.downstreams {
		add(downstream)
	}

	return sniffers
}

func openPacketSniffer(ifc *net.Interface) (*packetSniffer, error) {
	filter := ndpFilterProgram()
	conn, err := packet.Listen(ifc, packet.Raw, int(unix.ETH_P_IPV6), &packet.Config{Filter: filter})
	if err != nil {
		return nil, fmt.Errorf("open raw packet socket ifindex %d: %w", ifc.Index, err)
	}

	if err := enableAllMulticast(conn, ifc.Index); err != nil {
		_ = conn.Close()

		return nil, fmt.Errorf("enable all-multicast ifindex %d: %w", ifc.Index, err)
	}

	return &packetSniffer{conn: conn, ifindex: ifc.Index, ifname: ifc.Name}, nil
}

func ndpFilterProgram() []bpf.RawInstruction {
	return []bpf.RawInstruction{
		// Load IPv6 Next Header (offset ethernet + 6)
		{Op: unix.BPF_LD + unix.BPF_B + unix.BPF_ABS, K: bpfNextHeaderOffset},
		// If not ICMPv6 (58), drop
		{Op: unix.BPF_JMP + unix.BPF_JEQ + unix.BPF_K, Jf: bpfDropJump, K: icmpv6NextHeader},
		// Load ICMPv6 type (offset ethernet + ipv6 header)
		{Op: unix.BPF_LD + unix.BPF_B + unix.BPF_ABS, K: bpfICMPTypeOffset},
		// Accept NS (135)
		{Op: unix.BPF_JMP + unix.BPF_JEQ + unix.BPF_K, Jt: bpfNSJump, K: icmpv6NS},
		// Accept NA (136)
		{Op: unix.BPF_JMP + unix.BPF_JEQ + unix.BPF_K, Jt: bpfNAJump, K: icmpv6NA},
		// Drop
		{Op: unix.BPF_RET + unix.BPF_K, K: 0},
		// Accept up to ND payload size
		{Op: unix.BPF_RET + unix.BPF_K, K: maxCaptureLen},
	}
}

func enableAllMulticast(conn *packet.Conn, ifindex int) error {
	if ifindex > math.MaxInt32 {
		return fmt.Errorf("%w: %d", errIfindexTooLarge, ifindex)
	}

	rawConn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("syscall conn: %w", err)
	}

	var sockErr error
	if err := rawConn.Control(func(fdDescriptor uintptr) {
		mreq := &unix.PacketMreq{
			Ifindex: int32(ifindex), //nolint:gosec // bounded by check above
			Type:    unix.PACKET_MR_ALLMULTI,
			Alen:    ethernetAddrLen,
		}
		sockErr = unix.SetsockoptPacketMreq(int(fdDescriptor), unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, mreq)
	}); err != nil {
		return fmt.Errorf("enable all-multicast control: %w", err)
	}

	if sockErr != nil {
		return fmt.Errorf("enable all-multicast setsockopt: %w", sockErr)
	}

	return nil
}

func (svc *Service) sniffLoop(sniffer *packetSniffer, pktConn *ipv6.PacketConn) {
	buf := make([]byte, snifferBufLen)

	for {
		bytesRead, _, err := sniffer.conn.ReadFrom(buf)
		if err != nil {
			switch {
			case errors.Is(err, net.ErrClosed), errors.Is(err, os.ErrClosed):
				return
			default:
				if svc.log != nil {
					svc.log.Warn("ndp sniffer recv failed", "iface", sniffer.ifname, "err", err)
				}
			}

			continue
		}

		svc.handleSniffed(sniffer, pktConn, buf[:bytesRead])
	}
}

func (svc *Service) handleSniffed(sniffer *packetSniffer, pktConn *ipv6.PacketConn, frame []byte) {
	if len(frame) < ethernetHeaderLen+ipv6HeaderLen+icmpHeaderMinLen { // ICMPv6 header min
		return
	}

	ipv6Hdr := frame[ethernetHeaderLen : ethernetHeaderLen+ipv6HeaderLen]
	payloadLen := int(binary.BigEndian.Uint16(ipv6Hdr[4:6]))
	totalLen := ethernetHeaderLen + ipv6HeaderLen + payloadLen
	if totalLen > len(frame) || payloadLen == 0 {
		return
	}

	src := net.IP(ipv6Hdr[8:24])
	dst := net.IP(ipv6Hdr[24:40])
	hopLimit := int(ipv6Hdr[7])

	icmpPayload := frame[ethernetHeaderLen+ipv6HeaderLen : totalLen]

	cm := &ipv6.ControlMessage{IfIndex: sniffer.ifindex, HopLimit: hopLimit, Dst: dst}
	ipSrc := &net.IPAddr{IP: src}

	svc.processPacket(pktConn, cm, ipSrc, icmpPayload)
}

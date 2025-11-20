//go:build linux

package testutil

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	gont "cunicu.li/gont/v2/pkg"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netns"
)

const expectedCIDRParts = 2
const (
	namePrefix          = "r"        // keep first char alpha
	randNameBytes       = 4          // 4 bytes -> 8 hex chars
	fallbackHexStr      = "deadbeef" // 8 chars; with prefix => 9 total
	fallbackHostID      = 0xbeef
	waitIfaceReadySleep = 100 * time.Millisecond
)

func randomHostID() uint16 {
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return fallbackHostID
	}

	return binary.BigEndian.Uint16(idBytes[:])
}

func randomNetnsName() string {
	buf := make([]byte, randNameBytes)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand should not fail; fallback deterministic string.
		return namePrefix + fallbackHexStr
	}

	return namePrefix + hex.EncodeToString(buf)
}

type Topology struct {
	Network    *gont.Network
	Router     *gont.Host
	Relay      *gont.Host
	Client     *gont.Host
	UpSwitch   *gont.Switch
	DownSwitch *gont.Switch
	RouterLLA  net.IPNet
	RouterGUA  net.IPNet
	ClientLLA  net.IPNet
}

func MustBuildTopology(t *testing.T) *Topology {
	t.Helper()

	name := randomNetnsName()

	network, err := gont.NewNetwork(name)
	require.NoError(t, err, "create gont network")

	t.Cleanup(func() { _ = network.Close() })

	upSwitch, err := network.AddSwitch("up")
	require.NoError(t, err, "add upstream switch")

	downSwitch, err := network.AddSwitch("down")
	require.NoError(t, err, "add downstream switch")

	routerLLA := MustCIDR(t, fmt.Sprintf("fe80::%x/64", randomHostID()))
	routerGUA := MustCIDR(t, fmt.Sprintf("2001:db8:%x::1/64", randomHostID()))

	router, err := network.AddHost("router",
		&gont.Interface{
			Name: "eth0",
			Node: upSwitch,
			Addresses: []net.IPNet{
				routerLLA,
				routerGUA,
			},
		},
	)
	require.NoError(t, err, "add router")

	relay, err := network.AddHost("relay",
		&gont.Interface{Name: "uplink", Node: upSwitch},
		&gont.Interface{Name: "downlink", Node: downSwitch},
	)
	require.NoError(t, err, "add relay")

	clientLLA := MustCIDR(t, fmt.Sprintf("fe80::%x/64", randomHostID()))

	client, err := network.AddHost("client",
		&gont.Interface{
			Name: "eth0",
			Node: downSwitch,
			Addresses: []net.IPNet{
				clientLLA,
			},
		},
	)
	require.NoError(t, err, "add client")

	// Enable forwarding on router and bring interfaces up (defensive)
	_, err = router.Run("sysctl", "-w", "net.ipv6.conf.all.forwarding=1")
	require.NoError(t, err, "enable forwarding")
	_, err = router.Run("ip", "link", "set", "eth0", "up")
	require.NoError(t, err, "router link up")
	_, err = client.Run("ip", "link", "set", "eth0", "up")
	require.NoError(t, err, "client link up")

	waitIfaceReady := func(host *gont.Host, ifName string) {
		_, _ = host.Run("sysctl", "-w", "net.ipv6.conf."+ifName+".accept_dad=0")
		for range 50 {
			cmd := host.Command("ip", "-6", "addr", "show", "dev", ifName, "tentative")
			out, _ := cmd.CombinedOutput()
			if strings.TrimSpace(string(out)) == "" {
				return
			}
			time.Sleep(waitIfaceReadySleep)
		}
		require.FailNowf(t, "iface not ready", "%s still tentative", ifName)
	}

	waitIfaceReady(router, "eth0")
	waitIfaceReady(client, "eth0")

	return &Topology{
		Network:    network,
		Router:     router,
		Relay:      relay,
		Client:     client,
		UpSwitch:   upSwitch,
		DownSwitch: downSwitch,
		RouterLLA:  routerLLA,
		RouterGUA:  routerGUA,
		ClientLLA:  clientLLA,
	}
}

// Close tears down the gont network; suitable for manual cleanup when t.Cleanup not used.
func (t *Topology) Close() {
	_ = t.Network.Close()
}

func RequireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		require.FailNow(t, "requires root (CAP_NET_ADMIN/RAW)")
	}
}

func RequireLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		require.FailNow(t, "linux only")
	}
}

func MustCIDR(t *testing.T, address string) net.IPNet {
	t.Helper()

	parts := strings.Split(address, "/")
	require.Len(t, parts, expectedCIDRParts, "invalid CIDR %q", address)

	addr := net.ParseIP(parts[0])
	require.NotNil(t, addr, "invalid IP in CIDR %q", address)

	ones, err := strconv.Atoi(parts[1])
	require.NoErrorf(t, err, "invalid mask in CIDR %q", address)

	bits := 128
	if addr.To4() != nil {
		bits = 32
		addr = addr.To4()
	}

	return net.IPNet{
		IP:   addr,
		Mask: net.CIDRMask(ones, bits),
	}
}

func WithNetNS(target netns.NsHandle, work func() error) (retErr error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	orig, err := netns.Get()
	if err != nil {
		return fmt.Errorf("get current namespace: %w", err)
	}
	defer func() {
		if closeErr := orig.Close(); closeErr != nil && retErr == nil {
			retErr = fmt.Errorf("close namespace handle: %w", closeErr)
		}
	}()
	defer func() {
		if setErr := netns.Set(orig); setErr != nil && retErr == nil {
			retErr = fmt.Errorf("restore namespace: %w", setErr)
		}
	}()
	if err := netns.Set(target); err != nil {
		return fmt.Errorf("switch namespace: %w", err)
	}

	return work()
}

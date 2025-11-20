package ndp_test

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/iface"
	"github.com/jkoelker/ipv6relayd/pkg/ndp"
	"github.com/jkoelker/ipv6relayd/pkg/netutil"
	"github.com/jkoelker/ipv6relayd/pkg/testutil"
)

func TestLookupTargetHostIPReturnsClone(t *testing.T) {
	t.Parallel()

	svc := newHostLookupTestService(t, time.Hour, nil)
	target := net.ParseIP("2001:db8::10")
	original := net.ParseIP("fe80::1")

	svc.SeedTargetCache(target, original, "lan0")

	got := svc.LookupTargetHostIP(target)
	if got == nil || !got.Equal(original) {
		t.Fatalf("lookupTargetHostIP = %v, want %v", got, original)
	}

	// Mutating the returned slice must not affect the cached host IP.
	got[0] ^= 0xff

	second := svc.LookupTargetHostIP(target)
	if second == nil || !second.Equal(original) {
		t.Fatalf("lookupTargetHostIP second read = %v, want %v", second, original)
	}
}

func TestLookupTargetHostIPExpiresEntry(t *testing.T) {
	t.Parallel()

	ttl := 10 * time.Millisecond
	svc := newHostLookupTestService(t, ttl, nil)
	target := net.ParseIP("2001:db8::beef")

	svc.SeedTargetCache(target, net.ParseIP("fe80::1234"), "lan0")
	time.Sleep(ttl + time.Millisecond)

	if got := svc.LookupTargetHostIP(target); got != nil {
		t.Fatalf("expected nil after expiration, got %v", got)
	}
}

func TestSendRedirectRejectsUnspecifiedHost(t *testing.T) {
	t.Parallel()

	svc, iface, _ := newRedirectHardwareService(t, nil)
	payload := make([]byte, 128)

	if err := svc.SendRedirect(nil, payload, iface, nil, nil); err == nil {
		t.Fatalf("expected error for unspecified host")
	}
}

func TestResolveRedirectTargetHardwareSameInterface(t *testing.T) {
	t.Parallel()

	expected := net.HardwareAddr{0x10, 0x11, 0x12, 0x13, 0x14, 0x15}
	resolver := func(iface *net.Interface, ip net.IP) (net.HardwareAddr, error) {
		if iface.Name == "lan0" && ip.Equal(net.ParseIP("2001:db8:1::5")) {
			return netutil.CloneAddr(expected), nil
		}

		return nil, nil
	}

	svc, downstream, _ := newRedirectHardwareService(t, resolver)
	target := net.ParseIP("2001:db8:1::5")

	got := svc.ResolveRedirectTargetHardware(target, downstream)
	if !bytes.Equal(expected, got) {
		t.Fatalf("resolveRedirectTargetHardware got %v, want %v", got, expected)
	}
}

func TestResolveRedirectTargetHardwareFallsBackToProxyOnAlternateInterface(t *testing.T) {
	t.Parallel()

	resolver := func(iface *net.Interface, ip net.IP) (net.HardwareAddr, error) {
		if iface.Name == "lan0" && ip.Equal(net.ParseIP("2001:db8:1::6")) {
			return net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, nil
		}

		return nil, nil
	}

	svc, _, upstream := newRedirectHardwareService(t, resolver)
	target := net.ParseIP("2001:db8:1::6")

	got := svc.ResolveRedirectTargetHardware(target, upstream)
	if !bytes.Equal(upstream.HardwareAddr, got) {
		t.Fatalf("resolveRedirectTargetHardware got %v, want %v", got, upstream.HardwareAddr)
	}
}

func TestResolveRedirectTargetHardwareSkipsWhenNeighborUnknown(t *testing.T) {
	t.Parallel()

	resolver := func(_ *net.Interface, _ net.IP) (net.HardwareAddr, error) {
		return nil, nil
	}

	svc, downstream, _ := newRedirectHardwareService(t, resolver)
	target := net.ParseIP("2001:db8:1::7")

	if got := svc.ResolveRedirectTargetHardware(target, downstream); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

// helper constructors.
func newHostLookupTestService(
	tb testing.TB,
	ttl time.Duration,
	resolver func(*net.Interface, net.IP) (net.HardwareAddr, error),
) *ndp.Service {
	tb.Helper()

	mgr := iface.NewManager()
	logger := testutil.LoggerFromTB(tb)
	events, cancel := newTestInterfaceEvents()

	upstream := config.InterfaceConfig{IfName: "wan"}
	downstream := config.InterfaceConfig{IfName: "lan0"}

	ndpCfg := config.NDPConfig{
		Mode:           "relay",
		StaticEntries:  []config.NDPStaticBinding{},
		TargetCacheTTL: ttl,
	}

	svc, err := ndp.New(
		upstream,
		[]config.InterfaceConfig{downstream},
		ndpCfg,
		mgr,
		ndp.WithLogger(logger),
		ndp.WithNeighborResolver(resolver),
		ndp.WithInterfaceAddrs(stubInterfaceAddrs()),
		ndp.WithInterfaceEvents(events, cancel),
	)
	if err != nil {
		tb.Fatalf("failed to build ndp service: %v", err)
	}

	return svc
}

func newRedirectHardwareService(
	t *testing.T,
	resolver func(*net.Interface, net.IP) (net.HardwareAddr, error),
) (*ndp.Service, *net.Interface, *net.Interface) {
	t.Helper()

	mgr := iface.NewManager()
	logger := testutil.LoggerFromTB(t)
	events, cancel := newTestInterfaceEvents()

	downstream := &net.Interface{
		Name:         "lan0",
		Index:        2,
		HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
	}
	upstream := &net.Interface{
		Name:         "wan",
		Index:        1,
		HardwareAddr: net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
	}

	mgr.Inject(downstream.Name, downstream)
	mgr.Inject(upstream.Name, upstream)

	ndpCfg := config.NDPConfig{
		Mode: "relay",
		StaticEntries: []config.NDPStaticBinding{
			{Prefix: "2001:db8:1::/64", Interface: downstream.Name},
		},
	}

	svc, err := ndp.New(
		config.InterfaceConfig{IfName: upstream.Name},
		[]config.InterfaceConfig{{IfName: downstream.Name}},
		ndpCfg,
		mgr,
		ndp.WithLogger(logger),
		ndp.WithNeighborResolver(resolver),
		ndp.WithInterfaceAddrs(stubInterfaceAddrs()),
		ndp.WithInterfaceEvents(events, cancel),
	)
	if err != nil {
		t.Fatalf("failed to build ndp service: %v", err)
	}

	return svc, downstream, upstream
}

func stubInterfaceAddrs() func(*net.Interface) ([]net.Addr, error) {
	return func(ifc *net.Interface) ([]net.Addr, error) {
		if ifc == nil {
			return nil, nil
		}

		ip := net.ParseIP("fe80::" + ifc.Name)
		if ip == nil {
			ip = net.ParseIP("fe80::1")
		}

		return []net.Addr{&net.IPNet{IP: ip, Mask: net.CIDRMask(64, 128)}}, nil
	}
}

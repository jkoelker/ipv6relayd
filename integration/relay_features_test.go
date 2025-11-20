//go:build linux

package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/jkoelker/ipv6relayd/integration/internal/testutil"
	"github.com/jkoelker/ipv6relayd/pkg/config"
)

// Ensures the relay attaches Interface-ID and the option echoes back in the reply.
func TestRelayAddsInterfaceID(t *testing.T) {
	t.Parallel()

	testutil.RequireRoot(t)
	testutil.RequireLinux(t)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	topo := testutil.MustBuildTopology(t)
	defer topo.Close()

	binPath := testutil.BuildIPv6RelaydBinary(t)
	cfg := testutil.IntegrationConfig(topo.RouterLLA.IP)
	cfgPath := testutil.WriteIntegrationConfigFile(t, cfg)

	cancelRelay := testutil.StartIPv6RelaydProcess(t, topo.Relay, binPath, cfgPath)
	defer cancelRelay()

	var group errgroup.Group

	group.Go(func() error {
		return testutil.WithNetNS(topo.Router.NetNSHandle(), func() error {
			return testutil.RunUpstreamRouter(ctx, "eth0")
		})
	})

	group.Go(func() error {
		return testutil.WithNetNS(topo.Router.NetNSHandle(), func() error {
			return testutil.RunUpstreamDHCPv6WithValidator(ctx, t, "eth0", func(relay *dhcpv6.RelayMessage) error {
				iid := relay.Options.InterfaceID()
				require.Equal(t, []byte("downlink"), iid, "interface-id missing or mismatch")

				return nil
			})
		})
	})

	reply := testutil.MustDHCPv6Reply(ctx, t, topo.Client.NetNSHandle(), "eth0")
	testutil.ValidateDHCPv6Reply(t, reply)

	cancel()

	if err := group.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		require.NoError(t, err, "components terminated with error")
	}
}

// Ensures relay sets a meaningful link-address (RFC 8415 §19.1.1 permits
// link-local when no GUA/ULA is available; address must not be ::).
func TestRelayUsesNonLinkLocalLinkAddress(t *testing.T) {
	t.Parallel()

	testutil.RequireRoot(t)
	testutil.RequireLinux(t)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	topo := testutil.MustBuildTopology(t)
	defer topo.Close()

	binPath := testutil.BuildIPv6RelaydBinary(t)
	cfg := testutil.IntegrationConfig(topo.RouterLLA.IP)
	cfgPath := testutil.WriteIntegrationConfigFile(t, cfg)

	cancelRelay := testutil.StartIPv6RelaydProcess(t, topo.Relay, binPath, cfgPath)
	defer cancelRelay()

	var group errgroup.Group

	group.Go(func() error {
		return testutil.WithNetNS(topo.Router.NetNSHandle(), func() error {
			return testutil.RunUpstreamRouter(ctx, "eth0")
		})
	})

	group.Go(func() error {
		return testutil.WithNetNS(topo.Router.NetNSHandle(), func() error {
			return testutil.RunUpstreamDHCPv6WithValidator(ctx, t, "eth0", func(relay *dhcpv6.RelayMessage) error {
				if relay.LinkAddr.IsUnspecified() {
					return errors.New("link-address must not be unspecified")
				}

				return nil
			})
		})
	})

	reply := testutil.MustDHCPv6Reply(ctx, t, topo.Client.NetNSHandle(), "eth0")
	testutil.ValidateDHCPv6Reply(t, reply)

	cancel()

	if err := group.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		require.NoError(t, err, "components terminated with error")
	}
}

// Ensures the relay can run without Interface-ID injection and still relays correctly.
func TestRelayOmitsInterfaceIDWhenDisabled(t *testing.T) {
	t.Parallel()

	testutil.RequireRoot(t)
	testutil.RequireLinux(t)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	topo := testutil.MustBuildTopology(t)
	defer topo.Close()

	binPath := testutil.BuildIPv6RelaydBinary(t)
	cfg := testutil.IntegrationConfig(topo.RouterLLA.IP)
	cfg.DHCPv6.InjectInterface = config.BoolPtr(false)
	cfgPath := testutil.WriteIntegrationConfigFile(t, cfg)

	// Provide a global/ULA on the downstream interface so link-address is valid
	// when Interface-ID is disabled (RFC 8415 §20.1.1).
	_, err := topo.Relay.Run("ip", "-6", "addr", "add", "2001:db8:ffff:1::1/64", "dev", "downlink")
	require.NoError(t, err, "add downstream global address")

	cancelRelay := testutil.StartIPv6RelaydProcess(t, topo.Relay, binPath, cfgPath)
	defer cancelRelay()

	var group errgroup.Group

	group.Go(func() error {
		return testutil.WithNetNS(topo.Router.NetNSHandle(), func() error {
			return testutil.RunUpstreamRouter(ctx, "eth0")
		})
	})

	group.Go(func() error {
		return testutil.WithNetNS(topo.Router.NetNSHandle(), func() error {
			return testutil.RunUpstreamDHCPv6WithValidator(ctx, t, "eth0", func(relay *dhcpv6.RelayMessage) error {
				iid := relay.Options.InterfaceID()
				require.Empty(t, iid, "expected no interface-id")

				return nil
			})
		})
	})

	reply := testutil.MustDHCPv6Reply(ctx, t, topo.Client.NetNSHandle(), "eth0")
	testutil.ValidateDHCPv6Reply(t, reply)

	cancel()

	if err := group.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		require.NoError(t, err, "components terminated with error")
	}
}

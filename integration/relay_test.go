//go:build linux

package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/jkoelker/ipv6relayd/integration/internal/testutil"
)

func TestRelayRAAndDHCPv6(t *testing.T) {
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
			return testutil.RunUpstreamDHCPv6(ctx, t, "eth0")
		})
	})

	advCapture := testutil.MustRouterAdvertisement(ctx, t, topo.Client.NetNSHandle())
	testutil.ValidateRouterAdvertisement(t, advCapture, false, false)

	reply := testutil.MustDHCPv6Reply(ctx, t, topo.Client.NetNSHandle(), "eth0")
	testutil.ValidateDHCPv6Reply(t, reply)

	cancel()

	if err := group.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		require.NoError(t, err, "components terminated with error")
	}
}

func TestRelayRAFlagsFollowDHCPv6Enablement(t *testing.T) {
	t.Parallel()
	testutil.RequireRoot(t)
	testutil.RequireLinux(t)

	t.Run("enabled preserves upstream M/O", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
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

		advCapture := testutil.MustRouterAdvertisement(ctx, t, topo.Client.NetNSHandle())
		testutil.ValidateRouterAdvertisement(t, advCapture, false, false)
		cancel()
		if err := group.Wait(); err != nil && !errors.Is(err, context.Canceled) {
			require.NoError(t, err)
		}
	})

	t.Run("disabled preserves upstream M/O", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()

		topo := testutil.MustBuildTopology(t)
		defer topo.Close()

		binPath := testutil.BuildIPv6RelaydBinary(t)
		cfg := testutil.IntegrationConfig(topo.RouterLLA.IP)
		cfg.DHCPv6.Enabled = false
		cfgPath := testutil.WriteIntegrationConfigFile(t, cfg)

		cancelRelay := testutil.StartIPv6RelaydProcess(t, topo.Relay, binPath, cfgPath)
		defer cancelRelay()

		var group errgroup.Group
		group.Go(func() error {
			return testutil.WithNetNS(topo.Router.NetNSHandle(), func() error {
				return testutil.RunUpstreamRouter(ctx, "eth0")
			})
		})

		advCapture := testutil.MustRouterAdvertisement(ctx, t, topo.Client.NetNSHandle())
		testutil.ValidateRouterAdvertisement(t, advCapture, false, false)
		cancel()
		if err := group.Wait(); err != nil && !errors.Is(err, context.Canceled) {
			require.NoError(t, err)
		}
	})
}

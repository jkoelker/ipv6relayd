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
)

// RFC 8415 compliance smoke: relay-forward must carry Interface-ID and proper hop-count.
func TestRelayForwardCarriesInterfaceID(t *testing.T) {
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

	validate := func(relay *dhcpv6.RelayMessage) error {
		iid := relay.Options.InterfaceID()
		if len(iid) == 0 {
			return errors.New("missing interface-id option")
		}
		if relay.HopCount != 0 {
			return errors.New("unexpected hop-count on first relay hop")
		}

		return nil
	}

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
			return testutil.RunUpstreamDHCPv6WithValidator(ctx, t, "eth0", validate)
		})
	})

	_ = testutil.MustDHCPv6Reply(ctx, t, topo.Client.NetNSHandle(), "eth0")

	cancel()

	if err := group.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		require.NoError(t, err, "components terminated with error")
	}
}

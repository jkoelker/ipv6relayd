package ra_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/iface"
	"github.com/jkoelker/ipv6relayd/pkg/ifmon"
	"github.com/jkoelker/ipv6relayd/pkg/ra"
	"github.com/jkoelker/ipv6relayd/pkg/testutil"
)

func newTestRAEvents() (<-chan ifmon.InterfaceEvent, func()) {
	ch := make(chan ifmon.InterfaceEvent)
	close(ch)

	return ch, func() {}
}

func newTestRAService(
	t *testing.T,
	upstream *net.Interface,
	downstreams []*net.Interface,
	cfg config.RAConfig,
	opts ...func(*ra.Options),
) *ra.Service {
	t.Helper()

	events, cancel := newTestRAEvents()
	mgr := iface.NewManager()

	mgr.Inject(upstream.Name, upstream)

	downstreamCfgs := make([]config.InterfaceConfig, 0, len(downstreams))
	for _, ifc := range downstreams {
		mgr.Inject(ifc.Name, ifc)
		downstreamCfgs = append(downstreamCfgs, config.InterfaceConfig{IfName: ifc.Name})
	}

	if cfg.Mode == "" {
		cfg.Mode = "relay"
	}

	baseOpts := []func(*ra.Options){
		ra.WithLogger(testutil.LoggerFromTB(t)),
		ra.WithInterfaceEvents(events, cancel),
	}
	baseOpts = append(baseOpts, opts...)

	svc, err := ra.New(config.InterfaceConfig{IfName: upstream.Name}, downstreamCfgs, cfg, mgr, baseOpts...)
	require.NoError(t, err)

	return svc
}

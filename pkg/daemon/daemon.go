package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/vishvananda/netlink"
	"golang.org/x/sync/errgroup"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/dhcpv6"
	"github.com/jkoelker/ipv6relayd/pkg/iface"
	"github.com/jkoelker/ipv6relayd/pkg/ifmon"
	"github.com/jkoelker/ipv6relayd/pkg/ndp"
	"github.com/jkoelker/ipv6relayd/pkg/netstate"
	"github.com/jkoelker/ipv6relayd/pkg/ra"
)

const defaultComponentCapacity = 4

var (
	ErrNilConfig         = errors.New("configuration is nil")
	ErrNilLogger         = errors.New("logger is nil")
	ErrNoServicesEnabled = errors.New("no services enabled; enable at least one of RA, DHCPv6, or NDP")
)

type component interface {
	Run(ctx context.Context) error
	Name() string
}

type componentBuilder struct {
	init  func() (component, error)
	label string
}

type Daemon struct {
	components     []component
	log            *slog.Logger
	ifaceMonitor   *ifmon.Monitor
	linkLocalCache *netstate.LinkLocalCache
	eventBus       *interfaceEventBus
}

func New(cfg *config.Config, logger *slog.Logger) (*Daemon, error) {
	if cfg == nil {
		return nil, ErrNilConfig
	}
	if logger == nil {
		return nil, ErrNilLogger
	}

	monitor := ifmon.New(ifmon.WithLogger(logger.With("component", "ifmon")))
	linkLocalCache := netstate.NewLinkLocalCache()
	eventBus := newInterfaceEventBus(logger.With("component", "iface-events"))

	comps, err := buildComponents(cfg, logger, linkLocalCache, eventBus)
	if err != nil {
		return nil, err
	}
	if len(comps) == 0 {
		return nil, ErrNoServicesEnabled
	}

	return &Daemon{
		components:     comps,
		log:            logger.With("component", "daemon"),
		ifaceMonitor:   monitor,
		linkLocalCache: linkLocalCache,
		eventBus:       eventBus,
	}, nil
}

func (d *Daemon) Run(ctx context.Context) error {
	group, ctx := errgroup.WithContext(ctx)

	if d.ifaceMonitor != nil {
		if err := d.ifaceMonitor.Run(ctx); err != nil {
			return fmt.Errorf("start interface monitor: %w", err)
		}
		if err := d.startInterfaceWatcher(ctx); err != nil {
			return err
		}
	}
	if d.eventBus != nil {
		go func() {
			<-ctx.Done()
			d.eventBus.Close()
		}()
	}

	for _, comp := range d.components {
		group.Go(func() error {
			d.log.Info("starting component", "name", comp.Name())
			err := comp.Run(ctx)
			if err != nil && !errors.Is(err, context.Canceled) {
				d.log.Error("component exited with error", "name", comp.Name(), "err", err)

				return fmt.Errorf("component %s: %w", comp.Name(), err)
			}

			d.log.Info("component stopped", "name", comp.Name())

			return nil
		})
	}

	if err := group.Wait(); err != nil {
		return fmt.Errorf("daemon components: %w", err)
	}

	return nil
}

func appendComponent(comps []component, builder func() (component, error), errLabel string) ([]component, error) {
	svc, err := builder()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errLabel, err)
	}
	if svc != nil {
		comps = append(comps, svc)
	}

	return comps, nil
}

func buildComponents(
	cfg *config.Config,
	logger *slog.Logger,
	cache *netstate.LinkLocalCache,
	bus *interfaceEventBus,
) ([]component, error) {
	ifaces := iface.NewManager()
	builders := serviceBuilders(cfg, ifaces, logger, cache, bus)

	comps := make([]component, 0, defaultComponentCapacity)
	comps, err := appendComponents(comps, builders)
	if err != nil {
		return nil, err
	}

	return comps, nil
}

func appendComponents(comps []component, builders []componentBuilder) ([]component, error) {
	var err error
	for _, builder := range builders {
		comps, err = appendComponent(comps, builder.init, builder.label)
		if err != nil {
			return nil, err
		}
	}

	return comps, nil
}

func serviceBuilders(
	cfg *config.Config,
	ifaces *iface.Manager,
	logger *slog.Logger,
	cache *netstate.LinkLocalCache,
	bus *interfaceEventBus,
) []componentBuilder {
	builders := make([]componentBuilder, 0, defaultComponentCapacity)

	newEvents := func() (<-chan ifmon.InterfaceEvent, func()) {
		if bus == nil {
			return nil, func() {}
		}

		return bus.Subscribe()
	}

	if isModeEnabled(cfg.RA.Mode) {
		builders = append(builders, componentBuilder{
			init: func() (component, error) {
				events, cancel := newEvents()
				svc, err := ra.New(
					cfg.Upstream,
					cfg.Downstreams,
					cfg.RA,
					ifaces,
					ra.WithLogger(logger),
					ra.WithDHCPv6Enabled(cfg.DHCPv6.Enabled),
					ra.WithLinkLocalCache(cache),
					ra.WithInterfaceEvents(events, cancel),
				)
				if err != nil {
					cancel()

					return nil, fmt.Errorf("init ra service: %w", err)
				}

				return svc, nil
			},
			label: "init router advertisements",
		})
	}

	if cfg.DHCPv6.Enabled {
		builders = append(builders, componentBuilder{
			init: func() (component, error) {
				events, cancel := newEvents()
				svc, err := dhcpv6.New(
					cfg.Upstream,
					cfg.Downstreams,
					cfg.DHCPv6,
					ifaces,
					dhcpv6.WithLogger(logger),
					dhcpv6.WithLinkLocalCache(cache),
					dhcpv6.WithInterfaceEvents(events, cancel),
				)
				if err != nil {
					cancel()

					return nil, fmt.Errorf("init dhcpv6 service: %w", err)
				}

				return svc, nil
			},
			label: "init dhcpv6",
		})
	}

	if isModeEnabled(cfg.NDP.Mode) {
		builders = append(builders, componentBuilder{
			init: func() (component, error) {
				events, cancel := newEvents()
				svc, err := ndp.New(
					cfg.Upstream,
					cfg.Downstreams,
					cfg.NDP,
					ifaces,
					ndp.WithLogger(logger),
					ndp.WithLinkLocalCache(cache),
					ndp.WithInterfaceEvents(events, cancel),
				)
				if err != nil {
					cancel()

					return nil, fmt.Errorf("init ndp service: %w", err)
				}

				return svc, nil
			},
			label: "init ndp",
		})
	}

	return builders
}

func isModeEnabled(mode string) bool {
	return mode != "" && mode != "disabled"
}

func (d *Daemon) startInterfaceWatcher(ctx context.Context) error {
	if d.ifaceMonitor == nil {
		return nil
	}

	watcher := ifmon.NewWatcher(d.ifaceMonitor)

	linkHandler := func(_ context.Context, update netlink.LinkUpdate) {
		name := linkName(int(update.Index), update.Link)
		if d.log != nil {
			d.log.Debug("link update received", "ifindex", update.Index, "ifname", name)
		}
		d.handleInterfaceEvent("link update", int(update.Index), name)
	}

	addrHandler := func(_ context.Context, update netlink.AddrUpdate) {
		name := linkName(update.LinkIndex, nil)
		if d.log != nil {
			d.log.Debug("address update received", "ifindex", update.LinkIndex, "ifname", name)
		}
		d.handleInterfaceEvent("address update", update.LinkIndex, name)
	}

	if err := watcher.Start(ctx, linkHandler, addrHandler); err != nil {
		return fmt.Errorf("start interface watcher: %w", err)
	}

	return nil
}

func (d *Daemon) handleInterfaceEvent(reason string, ifIndex int, ifName string) {
	if d.linkLocalCache != nil {
		if ifName != "" {
			d.linkLocalCache.InvalidateName(ifName)
		}
		if ifIndex != 0 {
			d.linkLocalCache.InvalidateIndex(ifIndex)
		}
	}

	if d.eventBus != nil {
		d.eventBus.Publish(ifmon.InterfaceEvent{Reason: reason, IfIndex: ifIndex, IfName: ifName})
	}
}

func linkName(index int, link netlink.Link) string {
	if link != nil {
		if attrs := link.Attrs(); attrs != nil && attrs.Name != "" {
			return attrs.Name
		}
	}

	if index == 0 {
		return ""
	}

	resolved, err := netlink.LinkByIndex(index)
	if err != nil || resolved == nil {
		return ""
	}

	if attrs := resolved.Attrs(); attrs != nil {
		return attrs.Name
	}

	return ""
}

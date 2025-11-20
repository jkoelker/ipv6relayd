package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/urfave/cli/v2"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/daemon"
)

var (
	// ErrUnknownLogLevel indicates the provided log level string is not supported.
	ErrUnknownLogLevel = errors.New("unknown log level")

	errDownstreamRequiresUpstream  = errors.New("--downstream requires --upstream")
	errUpstreamRequiresDownstream  = errors.New("--upstream requires at least one --downstream")
	errDownstreamInterfaceRequired = errors.New("downstreams entry must not be empty")
)

type RunOptions struct {
	ConfigPath  string
	LogLevel    string
	Upstream    string
	Downstreams []string
}

func (o RunOptions) inlineConfigRequested() bool {
	return o.Upstream != "" || len(o.Downstreams) > 0
}

func Run() *cli.Command {
	return &cli.Command{
		Name:  "run",
		Usage: "Run the relay daemon",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "upstream",
				Usage: "Name of the upstream interface (enables inline minimal config)",
			},
			&cli.StringSliceFlag{
				Name:  "downstream",
				Usage: "Name of a downstream interface (repeat flag for multiple)",
			},
		},
		Action: func(c *cli.Context) error {
			opts := RunOptions{
				ConfigPath:  c.String("config"),
				LogLevel:    c.String("log-level"),
				Upstream:    c.String("upstream"),
				Downstreams: c.StringSlice("downstream"),
			}

			if err := runDaemon(opts); err != nil {
				return cli.Exit(err.Error(), exitFailure)
			}

			return nil
		},
	}
}

func runDaemon(opts RunOptions) error {
	level, err := parseLevel(opts.LogLevel)
	if err != nil {
		return fmt.Errorf("invalid log level %q: %w", opts.LogLevel, err)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	cfg, err := LoadRunConfig(opts)
	if err != nil {
		if opts.inlineConfigRequested() {
			logger.Error(
				"failed to build inline config",
				"upstream",
				opts.Upstream,
				"downstreams",
				opts.Downstreams,
				"err",
				err,
			)

			return fmt.Errorf("build config from flags: %w", err)
		}

		logger.Error("failed to load config", "path", opts.ConfigPath, "err", err)

		return fmt.Errorf("load config: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	relayDaemon, err := daemon.New(cfg, logger)
	if err != nil {
		logger.Error("failed to initialize daemon", "err", err)

		return fmt.Errorf("init daemon: %w", err)
	}

	if err := relayDaemon.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("daemon stopped unexpectedly", "err", err)

		return fmt.Errorf("run daemon: %w", err)
	}

	return nil
}

func parseLevel(value string) (slog.Level, error) {
	switch value {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("%w: %s", ErrUnknownLogLevel, value)
	}
}

func LoadRunConfig(opts RunOptions) (*config.Config, error) {
	if !opts.inlineConfigRequested() {
		cfg, err := config.Load(opts.ConfigPath)
		if err != nil {
			return nil, fmt.Errorf("load config %q: %w", opts.ConfigPath, err)
		}

		return cfg, nil
	}

	if opts.Upstream == "" {
		return nil, errDownstreamRequiresUpstream
	}

	if len(opts.Downstreams) == 0 {
		return nil, errUpstreamRequiresDownstream
	}

	cfg := &config.Config{
		Upstream: config.InterfaceConfig{IfName: opts.Upstream},
	}

	// When running from CLI flags without a config file, default DHCPv6 relay on
	// and include relay-interface-id so behavior matches the sample config.
	cfg.DHCPv6.Enabled = true
	cfg.DHCPv6.InjectInterface = config.BoolPtr(true)

	cfg.Downstreams = make([]config.InterfaceConfig, len(opts.Downstreams))
	for idx, ifName := range opts.Downstreams {
		if ifName == "" {
			return nil, fmt.Errorf("downstreams[%d]: %w", idx, errDownstreamInterfaceRequired)
		}

		cfg.Downstreams[idx] = config.InterfaceConfig{IfName: ifName}
	}

	cfg.ApplyDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate inline config: %w", err)
	}

	return cfg, nil
}

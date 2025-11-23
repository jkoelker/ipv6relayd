package main

import (
	"context"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/jkoelker/ipv6relayd/cmd/ipv6relayd/commands"
)

const (
	exitSuccess     = 0
	exitInvalidArgs = 2
	exitFailure     = 1
)

func main() {
	cmd := &cli.Command{
		Name:            "ipv6relayd",
		Usage:           "IPv6 relay daemon",
		HideHelpCommand: true,
		DefaultCommand:  "run",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "config",
				Value: "ipv6relayd.yaml",
				Usage: "Path to the configuration file (YAML or JSON)",
			},
			&cli.StringFlag{
				Name:  "log-level",
				Value: "info",
				Usage: "Log level: debug, info, warn, error",
			},
		},
		Commands: []*cli.Command{
			commands.Run(),
			commands.Config(),
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(exitFailure)
	}
}

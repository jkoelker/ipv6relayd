package commands

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
	"sigs.k8s.io/yaml"

	"github.com/jkoelker/ipv6relayd/pkg/config"
)

const sampleConfigPerm = 0o600

func Config() *cli.Command {
	return &cli.Command{
		Name:  "config",
		Usage: "Configuration helpers",
		Subcommands: []*cli.Command{
			{
				Name:  "default",
				Usage: "Print a sample configuration (YAML)",
				Action: func(_ *cli.Context) error {
					if err := printDefaultConfig(os.Stdout); err != nil {
						return cli.Exit(err.Error(), exitFailure)
					}

					return nil
				},
			},
			{
				Name:  "write",
				Usage: "Write a sample configuration (YAML) to a path",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "out",
						Value: "ipv6relayd.yaml",
						Usage: "Output path for the sample configuration",
					},
				},
				Action: func(c *cli.Context) error {
					if err := writeDefaultConfig(c.String("out")); err != nil {
						return cli.Exit(err.Error(), exitFailure)
					}

					return nil
				},
			},
		},
	}
}

func printDefaultConfig(out *os.File) error {
	data, err := yaml.Marshal(config.Default())
	if err != nil {
		return fmt.Errorf("encode default config: %w", err)
	}

	if _, err := out.Write(data); err != nil {
		return fmt.Errorf("write default config: %w", err)
	}

	return nil
}

func writeDefaultConfig(path string) error {
	data, err := yaml.Marshal(config.Default())
	if err != nil {
		return fmt.Errorf("encode default config: %w", err)
	}

	if err := os.WriteFile(path, data, sampleConfigPerm); err != nil {
		return fmt.Errorf("write default config to %s: %w", path, err)
	}

	return nil
}

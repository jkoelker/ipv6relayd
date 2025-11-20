package commands_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	ipv6commands "github.com/jkoelker/ipv6relayd/cmd/ipv6relayd/commands"
)

func TestLoadRunConfigInline(t *testing.T) {
	t.Parallel()

	opts := ipv6commands.RunOptions{
		Upstream:    "wan0",
		Downstreams: []string{"lan0", "lan1"},
	}

	cfg, err := ipv6commands.LoadRunConfig(opts)
	require.NoError(t, err)
	require.Equal(t, "wan0", cfg.Upstream.IfName)
	require.Len(t, cfg.Downstreams, 2)
	require.Equal(t, "lan0", cfg.Downstreams[0].IfName)
	require.Equal(t, "lan1", cfg.Downstreams[1].IfName)
	require.Equal(t, "relay", cfg.RA.Mode, "router advertisements should default to relay")
	require.Equal(t, "relay", cfg.NDP.Mode, "ndp should default to relay")
}

func TestLoadRunConfigInlineRequiresDownstream(t *testing.T) {
	t.Parallel()

	_, err := ipv6commands.LoadRunConfig(ipv6commands.RunOptions{Upstream: "wan0"})
	require.Error(t, err)
	require.ErrorContains(t, err, "--upstream requires at least one --downstream")
}

func TestLoadRunConfigInlineRequiresUpstream(t *testing.T) {
	t.Parallel()

	_, err := ipv6commands.LoadRunConfig(ipv6commands.RunOptions{Downstreams: []string{"lan0"}})
	require.Error(t, err)
	require.ErrorContains(t, err, "--downstream requires --upstream")
}

func TestLoadRunConfigFromFile(t *testing.T) {
	t.Parallel()

	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "ipv6relayd.yaml")
	configYAML := `---
upstream:
  ifname: wan0
downstreams:
  - ifname: lan0
`

	require.NoError(t, os.WriteFile(configPath, []byte(configYAML), 0o600))

	cfg, err := ipv6commands.LoadRunConfig(ipv6commands.RunOptions{ConfigPath: configPath})
	require.NoError(t, err)
	require.Equal(t, "wan0", cfg.Upstream.IfName)
	require.Len(t, cfg.Downstreams, 1)
	require.Equal(t, "lan0", cfg.Downstreams[0].IfName)
}

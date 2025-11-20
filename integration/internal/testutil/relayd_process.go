//go:build linux

package testutil

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	gont "cunicu.li/gont/v2/pkg"
	gc "cunicu.li/gont/v2/pkg/options/cmd"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"

	"github.com/jkoelker/ipv6relayd/pkg/config"
)

const (
	raUnsolicitedInterval = 5 * time.Second
	cfgFilePerm           = 0o600
)

func IntegrationConfig(upstreamLLA net.IP) *config.Config {
	return &config.Config{
		Upstream:    config.InterfaceConfig{IfName: "uplink"},
		Downstreams: []config.InterfaceConfig{{IfName: "downlink"}},
		RA: config.RAConfig{
			Mode:                "relay",
			UnsolicitedInterval: raUnsolicitedInterval,
		},
		DHCPv6: config.DHCPv6Config{
			Enabled:         true,
			Upstream:        upstreamLLA.String() + "%uplink",
			OverrideDNS:     []string{"2001:db8:53::53"},
			InjectInterface: config.BoolPtr(true),
		},
		NDP: config.NDPConfig{Mode: "relay"},
	}
}

func BuildIPv6RelaydBinary(t *testing.T) string {
	t.Helper()
	binPath := filepath.Join(t.TempDir(), "ipv6relayd-bin")
	root := os.Getenv("IPV6RELAYD_ROOT")
	if root == "" {
		// Backward compatibility with the previous project name.
		root = os.Getenv("RELAYSRC_ROOT")
	}
	if root == "" {
		wd, err := os.Getwd()
		require.NoError(t, err, "get working dir")
		root = filepath.Clean(filepath.Join(wd, ".."))
	}
	cmd := exec.CommandContext(t.Context(), "go", "build", "-o", binPath, "./cmd/ipv6relayd")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build ipv6relayd: %v\n%s", err, output)
	}

	return binPath
}

func WriteIntegrationConfigFile(t *testing.T, cfg *config.Config) string {
	t.Helper()
	cfgBytes, err := yaml.Marshal(cfg)
	require.NoError(t, err, "marshal integration config")

	path := filepath.Join(t.TempDir(), "ipv6relayd.yaml")
	require.NoError(t, os.WriteFile(path, cfgBytes, cfgFilePerm), "write integration config file")

	return path
}

func StartIPv6RelaydProcess(t *testing.T, relay *gont.Host, binPath, cfgPath string) context.CancelFunc {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())

	var combined bytes.Buffer
	cmd := relay.Command(
		binPath,
		"--config", cfgPath,
		"--log-level", "debug",
		gc.Context{Context: ctx},
		gc.Combined(&combined),
	)

	require.NoErrorf(t, cmd.Start(), "start ipv6relayd process. logs:\n%s", combined.String())

	var waitErr error
	done := make(chan struct{})
	go func() {
		waitErr = cmd.Wait()
		close(done)
	}()

	go func() {
		select {
		case <-done:
			if waitErr != nil && ctx.Err() == nil {
				t.Errorf("ipv6relayd exited early: %v\nlogs:\n%s", waitErr, combined.String())
			}
		case <-ctx.Done():
		}
	}()

	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			<-done
		}

		if waitErr != nil && ctx.Err() == nil {
			t.Logf("ipv6relayd exited: %v\n%s", waitErr, combined.String())
		}

		if t.Failed() {
			t.Logf("ipv6relayd logs:\n%s", combined.String())
		}
	})

	return cancel
}

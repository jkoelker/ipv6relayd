package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jkoelker/ipv6relayd/pkg/config"
)

func TestApplyDefaults(t *testing.T) {
	const relayMode = "relay"

	t.Parallel()

	t.Run("downstreams enable relay modes", func(t *testing.T) {
		t.Parallel()

		cfg := &config.Config{
			Downstreams: []config.InterfaceConfig{{IfName: "lan0"}},
		}

		cfg.ApplyDefaults()

		assert.Equal(t, relayMode, cfg.RA.Mode, "router advertisements mode")
		assert.Equal(t, relayMode, cfg.NDP.Mode, "ndp mode")
	})

	t.Run("no downstreams keeps modes disabled", func(t *testing.T) {
		t.Parallel()

		cfg := &config.Config{}
		wantMode := "disabled"

		cfg.ApplyDefaults()

		assert.Equal(t, wantMode, cfg.RA.Mode, "router advertisements mode")
		assert.Equal(t, wantMode, cfg.NDP.Mode, "ndp mode")
	})

	t.Run("explicit modes are preserved", func(t *testing.T) {
		t.Parallel()

		cfg := &config.Config{}
		cfg.RA.Mode = relayMode
		cfg.NDP.Mode = relayMode

		cfg.ApplyDefaults()

		assert.Equal(t, relayMode, cfg.RA.Mode, "router advertisements mode overwritten")
		assert.Equal(t, relayMode, cfg.NDP.Mode, "ndp mode overwritten")
	})
}

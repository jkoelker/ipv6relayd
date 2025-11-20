package dhcpv6

import (
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
)

// RFC 9096 §4 defines caps used for RA PIO lifetimes; apply the same ceilings
// to delegated prefixes we forward so we do not hand out excessively long PD
// lifetimes that would delay recovery from upstream failures.
const (
	NDPreferredLimit = 2700 * time.Second // 45 minutes
	NDValidLimit     = 5400 * time.Second // 90 minutes
)

// ClampIAPrefixLifetimes enforces RFC 8415 lifetime limits on IA_PD prefixes.
func ClampIAPrefixLifetimes(msg *dhcpv6.Message) {
	if msg == nil {
		return
	}

	for _, opt := range msg.Options.Get(dhcpv6.OptionIAPD) {
		pd, ok := opt.(*dhcpv6.OptIAPD)
		if !ok {
			continue
		}

		for _, inner := range pd.Options.Get(dhcpv6.OptionIAPrefix) {
			prefix, ok := inner.(*dhcpv6.OptIAPrefix)
			if !ok {
				continue
			}

			if prefix.ValidLifetime > NDValidLimit {
				prefix.ValidLifetime = NDValidLimit
			}

			if prefix.PreferredLifetime > NDPreferredLimit {
				prefix.PreferredLifetime = NDPreferredLimit
			}

			if prefix.PreferredLifetime > prefix.ValidLifetime {
				prefix.PreferredLifetime = prefix.ValidLifetime
			}
		}
	}
}

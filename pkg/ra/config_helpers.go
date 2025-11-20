package ra

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"

	"github.com/jkoelker/ipv6relayd/pkg/config"
)

func validateRAInputs(cfg config.RAConfig, downstreams []config.InterfaceConfig) error {
	if cfg.Mode == "server" {
		return ErrServerModeUnsupported
	}

	if len(downstreams) == 0 {
		return ErrRADownstreamRequired
	}

	return nil
}

func parseDNSRewriteEntries(entries []string, logger *slog.Logger) []net.IP {
	dnsRewrite := make([]net.IP, 0, len(entries))

	for _, entry := range entries {
		parsedIP := net.ParseIP(entry)
		if parsedIP == nil {
			logger.Warn("ignoring invalid dns rewrite entry", "value", entry)

			continue
		}

		if ipv4 := parsedIP.To4(); ipv4 != nil {
			logger.Warn("ignoring non-ipv6 dns rewrite entry", "value", entry)

			continue
		}

		dnsRewrite = append(dnsRewrite, parsedIP.To16())
	}

	return dnsRewrite
}

func normalizeDNSSL(domains []string, logger *slog.Logger) []string {
	if len(domains) == 0 {
		return nil
	}

	result := make([]string, 0, len(domains))

	for _, domain := range domains {
		canonical, err := config.CanonicalDomain(domain)
		if err != nil {
			logger.Warn("ignoring invalid dnssl rewrite entry", "value", domain, "err", err)

			continue
		}

		if !strings.HasSuffix(canonical, ".") {
			canonical += "."
		}

		result = append(result, canonical)
	}

	return result
}

func parsePref64Entries(values []string, _ *slog.Logger) ([]pref64Entry, error) {
	if len(values) == 0 {
		return nil, nil
	}

	entries := make([]pref64Entry, 0, len(values))

	for _, value := range values {
		val := strings.TrimSpace(value)
		if val == "" {
			continue
		}

		prefix, err := netip.ParsePrefix(val)
		if err != nil {
			return nil, fmt.Errorf("parse pref64 %q: %w", value, err)
		}

		if !prefix.Addr().Is6() {
			return nil, fmt.Errorf("%w: %s", ErrPref64NotIPv6, value)
		}

		if !isAllowedPref64Bits(prefix.Bits()) {
			return nil, fmt.Errorf("%w: %s (/%d)", ErrPref64InvalidPrefixLen, value, prefix.Bits())
		}

		masked := prefix.Masked()
		addr := masked.Addr()
		if !addr.Is6() {
			return nil, fmt.Errorf("%w: %s", ErrPref64InvalidAddress, value)
		}

		bytes := addr.As16()

		var entry pref64Entry
		entry.prefix = masked
		copy(entry.bytes[:], bytes[:len(entry.bytes)])
		entries = append(entries, entry)
	}

	return entries, nil
}

func isAllowedPref64Bits(bits int) bool {
	switch bits {
	case pref64Len32Bits,
		pref64Len40Bits,
		pref64Len48Bits,
		pref64Len56Bits,
		pref64Len64Bits,
		pref64Len96Bits:
		return true
	default:
		return false
	}
}

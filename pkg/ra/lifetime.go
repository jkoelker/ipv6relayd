package ra

import (
	"fmt"
	"time"

	"github.com/mdlayher/ndp"
)

const (
	maxUint16Int   = int64(^uint16(0))
	maxUint32Int   = int64(^uint32(0))
	pref64MaxUnits = 0x1fff
)

// Lifetime returns the minimum effective lifetime advertised within an RA payload.
func Lifetime(payload []byte) time.Duration {
	raMsg, err := ParseRouterAdvertisementPayload(payload)
	if err != nil {
		return 0
	}

	minLifetime, hasLifetime := baseRALifetime(raMsg)
	minLifetime, hasLifetime = reduceWithOptionLifetimes(raMsg, minLifetime, hasLifetime)
	if !hasLifetime {
		return 0
	}

	return minLifetime
}

func baseRALifetime(raMsg *ndp.RouterAdvertisement) (time.Duration, bool) {
	if raMsg.RouterLifetime <= 0 {
		return 0, false
	}

	return raMsg.RouterLifetime, true
}

func reduceWithOptionLifetimes(
	raMsg *ndp.RouterAdvertisement,
	current time.Duration,
	hasCurrent bool,
) (time.Duration, bool) {
	for _, opt := range raMsg.Options {
		lifetime, hasLifetimeField, zeroLifetime := optionLifetime(opt)
		if zeroLifetime {
			continue
		}

		if hasLifetimeField {
			if !hasCurrent || lifetime < current {
				current = lifetime
				hasCurrent = true
			}
		}
	}

	return current, hasCurrent
}

func maxRALifetime(raMsg *ndp.RouterAdvertisement) time.Duration {
	maxLifetime := raMsg.RouterLifetime

	for _, opt := range raMsg.Options {
		lifetime, hasLifetime, _ := optionLifetime(opt)
		if hasLifetime && lifetime > maxLifetime {
			maxLifetime = lifetime
		}

		if pio, ok := opt.(*ndp.PrefixInformation); ok {
			if preferred := pio.PreferredLifetime; preferred > maxLifetime {
				maxLifetime = preferred
			}
		}
	}

	return maxLifetime
}

func optionLifetime(opt ndp.Option) (time.Duration, bool, bool) {
	if lifetime, has, zero := prefixLifetime(opt); has || zero {
		return lifetime, has, zero
	}
	if lifetime, has, zero := routeLifetime(opt); has || zero {
		return lifetime, has, zero
	}
	if lifetime, has, zero := dnsLifetime(opt); has || zero {
		return lifetime, has, zero
	}
	if lifetime, has, zero := pref64Lifetime(opt); has || zero {
		return lifetime, has, zero
	}

	return 0, false, false
}

func clampRALifetimes(payload []byte, elapsed time.Duration) (bool, error) {
	raMsg, err := ParseRouterAdvertisementPayload(payload)
	if err != nil {
		return false, err
	}

	if elapsed < 0 {
		elapsed = 0
	}

	hasRemaining := clampRouterLifetimeField(raMsg, elapsed)

	options := make([]ndp.Option, 0, len(raMsg.Options))
	for _, opt := range raMsg.Options {
		if clampOptionLifetime(opt, elapsed) {
			options = append(options, opt)
			hasRemaining = true

			continue
		}

		// Keep options without lifetimes unchanged.
		if _, hasLifetime, _ := optionLifetime(opt); !hasLifetime {
			options = append(options, opt)
		}
	}

	raMsg.Options = options

	if !hasRemaining {
		return false, nil
	}

	buf, err := ndp.MarshalMessage(raMsg)
	if err != nil {
		return false, fmt.Errorf("marshal clamped RA: %w", err)
	}

	copy(payload, buf)

	return true, nil
}

func clampRouterLifetimeField(raMsg *ndp.RouterAdvertisement, elapsed time.Duration) bool {
	if raMsg.RouterLifetime == 0 {
		return false
	}

	remaining := raMsg.RouterLifetime - elapsed
	if remaining < time.Second {
		raMsg.RouterLifetime = 0

		return false
	}

	raMsg.RouterLifetime = remaining

	return true
}

func clampOptionLifetime(opt ndp.Option, elapsed time.Duration) bool {
	switch optVal := opt.(type) {
	case *ndp.PrefixInformation:
		return clampPrefixInfoOption(optVal, elapsed)
	case *ndp.RouteInformation:
		return clampStandardLifetimeOption(&optVal.RouteLifetime, elapsed)
	case *ndp.RecursiveDNSServer:
		return clampStandardLifetimeOption(&optVal.Lifetime, elapsed)
	case *ndp.DNSSearchList:
		return clampStandardLifetimeOption(&optVal.Lifetime, elapsed)
	case *ndp.PREF64:
		return clampPref64Option(optVal, elapsed)
	default:
		return false
	}
}

func clampPrefixInfoOption(pio *ndp.PrefixInformation, elapsed time.Duration) bool {
	clampedValid := clampStandardLifetimeOption(&pio.ValidLifetime, elapsed)
	_ = clampStandardLifetimeOption(&pio.PreferredLifetime, elapsed)

	return clampedValid
}

func clampStandardLifetimeOption(lifetime *time.Duration, elapsed time.Duration) bool {
	if lifetime == nil || *lifetime == 0 {
		return false
	}

	remaining := *lifetime - elapsed
	if remaining < time.Second {
		*lifetime = 0

		return false
	}

	*lifetime = remaining

	return true
}

func clampPref64Option(opt *ndp.PREF64, elapsed time.Duration) bool {
	if opt.Lifetime == 0 {
		return false
	}

	unit := time.Duration(pref64LifetimeUnits) * time.Second
	unitSeconds := int64(unit / time.Second)
	remainingSeconds := int64((opt.Lifetime - elapsed) / time.Second)
	if remainingSeconds < unitSeconds {
		opt.Lifetime = 0

		return false
	}

	// Round down to nearest unit and cap.
	remainingSeconds = (remainingSeconds / unitSeconds) * unitSeconds
	maxLifetime := time.Duration(pref64MaxUnits*pref64LifetimeUnits) * time.Second
	roundedDuration := time.Duration(remainingSeconds) * time.Second
	roundedDuration = min(roundedDuration, maxLifetime)

	opt.Lifetime = roundedDuration

	return true
}

func pruneZeroLifetimeOptions(raMsg *ndp.RouterAdvertisement) {
	options := raMsg.Options[:0]
	for _, opt := range raMsg.Options {
		_, _, zero := optionLifetime(opt)
		if zero {
			continue
		}
		options = append(options, opt)
	}
	raMsg.Options = options
}

func prefixLifetime(opt ndp.Option) (time.Duration, bool, bool) {
	pio, ok := opt.(*ndp.PrefixInformation)
	if !ok {
		return 0, false, false
	}

	return classifyLifetime(pio.ValidLifetime)
}

func routeLifetime(opt ndp.Option) (time.Duration, bool, bool) {
	route, ok := opt.(*ndp.RouteInformation)
	if !ok {
		return 0, false, false
	}

	return classifyLifetime(route.RouteLifetime)
}

func dnsLifetime(opt ndp.Option) (time.Duration, bool, bool) {
	if rdnss, ok := opt.(*ndp.RecursiveDNSServer); ok {
		return classifyLifetime(rdnss.Lifetime)
	}

	dnssl, ok := opt.(*ndp.DNSSearchList)
	if !ok {
		return 0, false, false
	}

	return classifyLifetime(dnssl.Lifetime)
}

func pref64Lifetime(opt ndp.Option) (time.Duration, bool, bool) {
	pref64, ok := opt.(*ndp.PREF64)
	if !ok {
		return 0, false, false
	}

	return classifyLifetime(pref64.Lifetime)
}

func classifyLifetime(lifetime time.Duration) (time.Duration, bool, bool) {
	if lifetime == 0 {
		return 0, false, true
	}

	return lifetime, true, false
}

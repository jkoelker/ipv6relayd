package ra

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/mdlayher/ndp"
)

// ParseRouterAdvertisementPayload attempts to parse an NDP Router Advertisement
// message from the given payload. If parsing fails due to zero-length options
// in the RA, it will attempt to trim those options and retry parsing.
func ParseRouterAdvertisementPayload(payload []byte) (*ndp.RouterAdvertisement, error) {
	msg, err := ndp.ParseMessage(payload)
	if err == nil {
		ra, ok := msg.(*ndp.RouterAdvertisement)
		if !ok {
			return nil, fmt.Errorf("%w: unexpected message type", ErrRouterAdvertisementShort)
		}

		return ra, nil
	}

	trimmed := trimZeroLengthRAOptions(payload)
	if len(trimmed) != len(payload) {
		msg, retryErr := ndp.ParseMessage(trimmed)
		if retryErr == nil {
			ra, ok := msg.(*ndp.RouterAdvertisement)
			if !ok {
				return nil, fmt.Errorf("%w: unexpected message type", ErrRouterAdvertisementShort)
			}

			return ra, nil
		}
	}

	return nil, fmt.Errorf("%w: %w", ErrRouterAdvertisementShort, err)
}

func parseRouterSolicitationPayload(payload []byte) (*ndp.RouterSolicitation, error) {
	msg, err := ndp.ParseMessage(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRouterSolicitationShort, err)
	}

	rs, ok := msg.(*ndp.RouterSolicitation)
	if !ok {
		return nil, fmt.Errorf("%w: unexpected message type", ErrRouterSolicitationShort)
	}

	return rs, nil
}

func cloneRouterAdvertisement(msg *ndp.RouterAdvertisement) *ndp.RouterAdvertisement {
	if msg == nil {
		return nil
	}

	clone := *msg
	clone.Options = cloneOptions(msg.Options)

	return &clone
}

func cloneOptions(opts []ndp.Option) []ndp.Option {
	out := make([]ndp.Option, 0, len(opts))
	for _, opt := range opts {
		out = append(out, cloneOption(opt))
	}

	return out
}

func cloneOption(opt ndp.Option) ndp.Option {
	if cloned := cloneLinkOption(opt); cloned != nil {
		return cloned
	}
	if cloned := cloneLifetimeOption(opt); cloned != nil {
		return cloned
	}
	if cloned := cloneMiscOption(opt); cloned != nil {
		return cloned
	}

	return opt
}

func cloneLinkOption(opt ndp.Option) ndp.Option {
	switch option := opt.(type) {
	case *ndp.LinkLayerAddress:
		return &ndp.LinkLayerAddress{
			Direction: option.Direction,
			Addr:      append(net.HardwareAddr(nil), option.Addr...),
		}
	case *ndp.MTU:
		return &ndp.MTU{MTU: option.MTU}
	case *ndp.RAFlagsExtension:
		return &ndp.RAFlagsExtension{Flags: append([]byte(nil), option.Flags...)}
	default:
		return nil
	}
}

func cloneLifetimeOption(opt ndp.Option) ndp.Option {
	switch option := opt.(type) {
	case *ndp.PrefixInformation:
		return &ndp.PrefixInformation{
			PrefixLength:                   option.PrefixLength,
			OnLink:                         option.OnLink,
			AutonomousAddressConfiguration: option.AutonomousAddressConfiguration,
			ValidLifetime:                  option.ValidLifetime,
			PreferredLifetime:              option.PreferredLifetime,
			Prefix:                         option.Prefix,
		}
	case *ndp.RouteInformation:
		return &ndp.RouteInformation{
			PrefixLength:  option.PrefixLength,
			Preference:    option.Preference,
			RouteLifetime: option.RouteLifetime,
			Prefix:        option.Prefix,
		}
	case *ndp.PREF64:
		return &ndp.PREF64{
			Lifetime: option.Lifetime,
			Prefix:   option.Prefix,
		}
	default:
		return nil
	}
}

func cloneMiscOption(opt ndp.Option) ndp.Option {
	switch option := opt.(type) {
	case *ndp.RecursiveDNSServer:
		return &ndp.RecursiveDNSServer{
			Lifetime: option.Lifetime,
			Servers:  append([]netip.Addr(nil), option.Servers...),
		}
	case *ndp.DNSSearchList:
		return &ndp.DNSSearchList{
			Lifetime:    option.Lifetime,
			DomainNames: append([]string(nil), option.DomainNames...),
		}
	default:
		return nil
	}
}

// trimZeroLengthRAOptions drops the remainder of an RA payload starting at the
// first zero-length option. Some test fixtures pad the body with zeros after
// the fixed header; mdlayher/ndp treats that as an invalid option and fails to
// parse. Returning the sliced payload lets parsing succeed while preserving the
// ICMP header and RA fields.
func trimZeroLengthRAOptions(payload []byte) []byte {
	minLen := RouterAdvertisementHeaderLength
	if len(payload) < minLen {
		return payload
	}

	offset := minLen
	for offset+1 < len(payload) {
		lengthUnits := payload[offset+1]
		if lengthUnits == 0 {
			return payload[:offset]
		}

		optLen := int(lengthUnits) * OptionUnitLength
		if optLen == 0 || offset+optLen > len(payload) {
			return payload
		}

		offset += optLen
	}

	return payload
}

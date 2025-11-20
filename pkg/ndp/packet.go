package ndp

import (
	"fmt"
	"net"

	"github.com/mdlayher/ndp"
)

func overwriteLinkLayer(option []byte, hardwareAddr net.HardwareAddr) {
	if len(option) < linkLayerOptionHeader {
		return
	}

	dataLen := len(option) - linkLayerOptionHeader
	copy(option[linkLayerOptionHeader:linkLayerOptionHeader+min(len(hardwareAddr), dataLen)], hardwareAddr)

	if extra := dataLen - len(hardwareAddr); extra > 0 {
		start := linkLayerOptionHeader + len(hardwareAddr)

		for i := start; i < linkLayerOptionHeader+dataLen; i++ {
			option[i] = 0
		}
	}
}

func allowSourceOption(src net.Addr) bool {
	if src == nil {
		return true
	}

	ipAddr, ok := src.(*net.IPAddr)
	if !ok {
		return true
	}

	return !ipAddr.IP.IsUnspecified()
}

func forEachNDPOption(payload []byte, headerLen int, optionHandler func(optType byte, option []byte) error) error {
	for offset := headerLen; offset+1 < len(payload); {
		optType := payload[offset]
		optLenUnits := payload[offset+1]
		if optLenUnits == 0 {
			return fmt.Errorf("%w", ErrInvalidOptionLength)
		}

		optLen := int(optLenUnits) * ndpOptionUnitLen
		if offset+optLen > len(payload) {
			return fmt.Errorf("type %d: %w", optType, ErrOptionTruncated)
		}

		if err := optionHandler(optType, payload[offset:offset+optLen]); err != nil {
			return err
		}

		offset += optLen
	}

	return nil
}

func dropNDPOptions(payload []byte, headerLen int, dropTypes ...byte) ([]byte, error) {
	if len(payload) <= headerLen || len(dropTypes) == 0 {
		return payload, nil
	}

	dropSet := make(map[byte]struct{}, len(dropTypes))
	for _, optType := range dropTypes {
		dropSet[optType] = struct{}{}
	}

	filtered := make([]byte, headerLen, len(payload))
	copy(filtered, payload[:headerLen])

	if err := forEachNDPOption(payload, headerLen, func(optType byte, option []byte) error {
		if _, drop := dropSet[optType]; drop {
			return nil
		}

		filtered = append(filtered, option...)

		return nil
	}); err != nil {
		return nil, err
	}

	return filtered, nil
}

func encodeLinkLayerOption(optType byte, hardwareAddr net.HardwareAddr) []byte {
	optLen := linkLayerOptionHeader + len(hardwareAddr)
	paddedLen := ((optLen + (ndpOptionUnitLen - 1)) / ndpOptionUnitLen) * ndpOptionUnitLen
	option := make([]byte, paddedLen)
	option[0] = optType
	option[1] = byte(paddedLen / ndpOptionUnitLen)
	copy(option[linkLayerOptionHeader:], hardwareAddr)

	return option
}

func extractSourceIP(addr net.Addr) net.IP {
	if ipAddr, ok := addr.(*net.IPAddr); ok {
		return ipAddr.IP
	}

	return nil
}

func buildNeighborSolicitationProbe(target net.IP, addr net.HardwareAddr) []byte {
	addrV6, ok := ipToAddr(target)
	if !ok {
		return nil
	}

	msg := &ndp.NeighborSolicitation{TargetAddress: addrV6}
	if opt := newLinkLayerOption(ndp.Source, addr); opt != nil {
		msg.Options = append(msg.Options, opt)
	}

	payload, err := ndp.MarshalMessage(msg)
	if err != nil {
		return nil
	}

	return payload
}

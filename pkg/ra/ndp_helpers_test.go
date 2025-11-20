package ra_test

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jkoelker/ipv6relayd/pkg/ra"
)

func TestParseRouterAdvertisementPayloadTrimsZeroLengthOption(t *testing.T) {
	t.Parallel()

	// Construct an ICMPv6 RA whose body is padded to 16 bytes, leaving a
	// zero-length option-like trailer that mdlayher/ndp would otherwise reject.
	payload := make([]byte, 4+ra.RouterAdvertisementHeaderLength)
	payload[0] = 134 // type: router advertisement
	payload[4] = 64  // Current Hop Limit
	binary.BigEndian.PutUint16(payload[6:8], 1800)

	ra, err := ra.ParseRouterAdvertisementPayload(payload)
	require.NoError(t, err)
	require.NotNil(t, ra)

	assert.Equal(t, 1800*time.Second, ra.RouterLifetime)
	assert.Empty(t, ra.Options)
}

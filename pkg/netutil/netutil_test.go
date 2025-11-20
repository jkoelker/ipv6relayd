package netutil_test

import (
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jkoelker/ipv6relayd/pkg/netutil"
)

func TestCloneAddr(t *testing.T) {
	t.Parallel()

	t.Run("nil stays nil", func(t *testing.T) {
		t.Parallel()

		var ip net.IP
		assert.Nil(t, netutil.CloneAddr(ip))
	})

	t.Run("clone differs from source", func(t *testing.T) {
		t.Parallel()

		src := net.IP{0xaa, 0xbb}
		cloned := netutil.CloneAddr(src)
		assert.NotSame(t, &src[0], &cloned[0], "expected distinct backing arrays")
		assert.Equal(t, src, cloned)
	})
}

func TestCloneSlice(t *testing.T) {
	t.Parallel()

	t.Run("empty slice returns nil", func(t *testing.T) {
		t.Parallel()

		assert.Nil(t, netutil.CloneSlice([]net.IP{}))
	})

	t.Run("deep copies members", func(t *testing.T) {
		t.Parallel()

		src := []net.IP{{0xaa}, {0xbb}}
		dup := netutil.CloneSlice(src)
		assert.NotSame(t, &src[0][0], &dup[0][0], "expected independent inner slices")
		assert.Equal(t, byte(0xbb), dup[1][0])
	})
}

func TestCloneMap(t *testing.T) {
	t.Parallel()

	assert.Nil(t, netutil.CloneMap(map[string][]net.IP{}))

	src := map[string][]net.IP{
		"eth0": {{0xaa}},
	}
	dup := netutil.CloneMap(src)
	dup["eth0"][0][0] = 0xff
	assert.NotEqual(t, byte(0xff), src["eth0"][0][0])
}

func TestParseConfiguredIP(t *testing.T) {
	t.Parallel()

	assert.Nil(t, netutil.ParseConfiguredIP(" "))
	parsed := netutil.ParseConfiguredIP("2001:db8::1")
	require.NotNil(t, parsed)
	assert.Equal(t, "2001:db8::1", parsed.String())
	assert.Nil(t, netutil.ParseConfiguredIP("192.0.2.1"))
}

func TestIsNoDeviceError(t *testing.T) {
	t.Parallel()

	assert.False(t, netutil.IsNoDeviceError(nil), "nil should not be ENODEV")
	assert.False(t, netutil.IsNoDeviceError(&net.OpError{Err: syscall.EIO}), "unexpected positive result for EIO")
	assert.True(t, netutil.IsNoDeviceError(&net.OpError{Err: syscall.ENODEV}), "expected true for ENODEV")
}

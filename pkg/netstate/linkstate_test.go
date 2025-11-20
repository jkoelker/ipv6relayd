package netstate_test

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/netstate"
)

const upstreamLinkLocal = "fe80::1"

func TestNewLinkInvalidUpstream(t *testing.T) {
	t.Parallel()

	_, err := netstate.NewLink(config.InterfaceConfig{LinkLocal: "not-an-ip"}, nil)
	require.Error(t, err)

	var parseErr *netstate.ParseError
	require.ErrorAs(t, err, &parseErr)
	assert.Equal(t, netstate.ParseErrorUpstream, parseErr.Kind)
}

func TestNewLinkInvalidDownstream(t *testing.T) {
	t.Parallel()

	_, err := netstate.NewLink(config.InterfaceConfig{}, []config.InterfaceConfig{{
		IfName:    "eth1",
		LinkLocal: "bad",
	}})
	require.Error(t, err)

	var parseErr *netstate.ParseError
	require.ErrorAs(t, err, &parseErr)
	assert.Equal(t, netstate.ParseErrorDownstream, parseErr.Kind)
}

func TestLinkResolveUpstreamPrefersOverride(t *testing.T) {
	t.Parallel()

	upstream := config.InterfaceConfig{LinkLocal: upstreamLinkLocal}
	called := false
	link, err := netstate.NewLink(upstream, nil, netstate.WithInterfaceAddrsFunc(func(*net.Interface) ([]net.Addr, error) {
		called = true

		return nil, nil
	}))
	require.NoError(t, err)

	resolvedUpstream, err := link.ResolveUpstream(&net.Interface{Name: "eth0"})
	require.NoError(t, err)
	assert.False(t, called, "unexpected interface resolution call")
	assert.Equal(t, upstreamLinkLocal, resolvedUpstream.String(), "unexpected upstream")
	resolvedUpstream[0] = 0xaa
	second, err := link.ResolveUpstream(&net.Interface{Name: "eth0"})
	require.NoError(t, err)
	assert.NotEqual(t, byte(0xaa), second[0], "expected cloned IP")
}

func TestLinkResolveUpstreamDiscoversLinkLocal(t *testing.T) {
	t.Parallel()

	resolver := netstate.WithInterfaceAddrsFunc(func(*net.Interface) ([]net.Addr, error) {
		return []net.Addr{
			mustCIDR(t, "2001:db8::1/128"),
			mustCIDR(t, "fe80::abcd/128"),
		}, nil
	})
	link, err := netstate.NewLink(config.InterfaceConfig{}, nil, resolver)
	require.NoError(t, err)

	addr, err := link.ResolveUpstream(&net.Interface{Name: "eth0"})
	require.NoError(t, err)
	assert.Equal(t, netip.MustParseAddr("fe80::abcd"), netip.MustParseAddr(addr.String()), "unexpected upstream")
}

func TestLinkResolveUpstreamNoLinkLocal(t *testing.T) {
	t.Parallel()

	resolver := netstate.WithInterfaceAddrsFunc(func(*net.Interface) ([]net.Addr, error) {
		return []net.Addr{mustCIDR(t, "2001:db8::1/64")}, nil
	})
	link, err := netstate.NewLink(config.InterfaceConfig{}, nil, resolver)
	require.NoError(t, err)

	_, err = link.ResolveUpstream(&net.Interface{Name: "eth0"})
	require.ErrorIs(t, err, netstate.ErrNoLinkLocalAddress)
}

func TestLinkResolveDownstreamPrefersOverride(t *testing.T) {
	t.Parallel()

	link, err := netstate.NewLink(config.InterfaceConfig{}, []config.InterfaceConfig{{
		IfName:    "eth1",
		LinkLocal: "fe80::2",
	}}, netstate.WithInterfaceAddrsFunc(func(*net.Interface) ([]net.Addr, error) {
		return nil, errors.New("should not be called")
	}))
	require.NoError(t, err)

	resolvedDownstream, err := link.ResolveDownstream(&net.Interface{Name: "eth1"}, "eth1")
	require.NoError(t, err)
	assert.Equal(t, "fe80::2", resolvedDownstream.String(), "unexpected downstream")
	resolvedDownstream[0] = 0xaa
	second, err := link.ResolveDownstream(&net.Interface{Name: "eth1"}, "eth1")
	require.NoError(t, err)
	assert.NotEqual(t, byte(0xaa), second[0], "expected cloned IP")
}

func TestLinkResolveDownstreamDiscovers(t *testing.T) {
	t.Parallel()

	resolver := netstate.WithInterfaceAddrsFunc(func(*net.Interface) ([]net.Addr, error) {
		return []net.Addr{mustCIDR(t, "fe80::99/128")}, nil
	})
	link, err := netstate.NewLink(config.InterfaceConfig{}, nil, resolver)
	require.NoError(t, err)

	addr, err := link.ResolveDownstream(&net.Interface{Name: "eth2"}, "eth2")
	require.NoError(t, err)
	assert.Equal(t, "fe80::99", addr.String(), "unexpected downstream")
}

package ifmon_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"github.com/jkoelker/ipv6relayd/pkg/ifmon"
	"github.com/jkoelker/ipv6relayd/pkg/testutil"
)

func TestMonitorDeliversLinkUpdates(t *testing.T) {
	t.Parallel()

	stub := &stubNetlink{}
	mon := newMonitorWithStub(t, stub)

	ctx := t.Context()

	require.NoError(t, mon.Run(ctx))

	subCtx, subCancel := context.WithCancel(ctx)
	defer subCancel()

	sub, err := mon.Subscribe(subCtx)
	require.NoError(t, err)

	update := netlink.LinkUpdate{
		IfInfomsg: nl.IfInfomsg{
			IfInfomsg: unix.IfInfomsg{Index: 42},
		},
	}
	stub.linkCh <- update

	select {
	case got, ok := <-sub.LinkUpdates:
		require.True(t, ok, "LinkUpdates closed unexpectedly")
		assert.Equal(t, update.Index, got.Index, "LinkUpdates index")
	case <-time.After(time.Second):
		require.FailNow(t, "timed out waiting for link update")
	}
}

func TestMonitorDeliversAddressUpdates(t *testing.T) {
	t.Parallel()

	stub := &stubNetlink{}
	mon := newMonitorWithStub(t, stub)

	ctx := t.Context()

	require.NoError(t, mon.Run(ctx))

	subCtx, subCancel := context.WithCancel(ctx)
	defer subCancel()

	sub, err := mon.Subscribe(subCtx)
	require.NoError(t, err)

	update := netlink.AddrUpdate{LinkIndex: 7}
	stub.addrCh <- update

	select {
	case got, ok := <-sub.AddressUpdates:
		require.True(t, ok, "AddressUpdates closed unexpectedly")
		assert.Equal(t, update.LinkIndex, got.LinkIndex, "AddressUpdates link index")
	case <-time.After(time.Second):
		require.FailNow(t, "timed out waiting for address update")
	}
}

func TestMonitorRunLinkSubscribeError(t *testing.T) {
	t.Parallel()

	stub := &stubNetlink{linkErr: errors.New("boom")}
	mon := newMonitorWithStub(t, stub)

	err := mon.Run(t.Context())
	require.Error(t, err, "expected error from Run when link subscribe fails")
}

func TestMonitorRunAddrSubscribeError(t *testing.T) {
	t.Parallel()

	stub := &stubNetlink{addrErr: errors.New("boom")}
	mon := newMonitorWithStub(t, stub)

	err := mon.Run(t.Context())
	require.Error(t, err, "expected error from Run when addr subscribe fails")
}

func TestSubscribeWithCanceledContext(t *testing.T) {
	t.Parallel()

	mon := ifmon.New(ifmon.WithLogger(testutil.LoggerFromTB(t)))

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := mon.Subscribe(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestMonitorShutdownClosesSubscribers(t *testing.T) {
	t.Parallel()

	stub := &stubNetlink{}
	mon := newMonitorWithStub(t, stub)

	ctx, cancel := context.WithCancel(t.Context())

	require.NoError(t, mon.Run(ctx))

	subCtx, subCancel := context.WithCancel(ctx)
	defer subCancel()

	sub, err := mon.Subscribe(subCtx)
	require.NoError(t, err)

	cancel()

	select {
	case _, ok := <-sub.LinkUpdates:
		require.False(t, ok, "LinkUpdates should be closed after shutdown")
	case <-time.After(time.Second):
		require.FailNow(t, "timeout waiting for LinkUpdates close")
	}
}

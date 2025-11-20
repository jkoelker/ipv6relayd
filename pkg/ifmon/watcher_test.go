package ifmon_test

import (
	"context"
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

func TestWatcherStartRequiresContext(t *testing.T) {
	t.Parallel()

	watcher := ifmon.NewWatcher(ifmon.New(ifmon.WithLogger(testutil.LoggerFromTB(t))))

	var nilCtx context.Context
	err := watcher.Start(nilCtx, nil, nil)
	require.ErrorIs(t, err, ifmon.ErrNilContext)
}

func TestWatcherStartRequiresMonitor(t *testing.T) {
	t.Parallel()

	watcher := ifmon.NewWatcher(nil)

	err := watcher.Start(context.Background(), nil, nil)
	require.ErrorIs(t, err, ifmon.ErrNotConfigured)
}

func TestWatcherDispatchesLinkUpdates(t *testing.T) {
	t.Parallel()

	stub := &stubNetlink{}
	watcher := ifmon.NewWatcher(newMonitorWithStub(t, stub))

	ctx := t.Context()
	updates := make(chan netlink.LinkUpdate, 1)

	require.NoError(t, watcher.Start(ctx, func(_ context.Context, update netlink.LinkUpdate) {
		updates <- update
	}, nil))

	update := netlink.LinkUpdate{
		IfInfomsg: nl.IfInfomsg{IfInfomsg: unix.IfInfomsg{Index: 11}},
	}
	stub.linkCh <- update

	select {
	case got := <-updates:
		assert.Equal(t, update.Index, got.Index, "link index")
	case <-time.After(time.Second):
		require.FailNow(t, "timeout waiting for link handler")
	}
}

func TestWatcherDispatchesAddrUpdates(t *testing.T) {
	t.Parallel()

	stub := &stubNetlink{}
	watcher := ifmon.NewWatcher(newMonitorWithStub(t, stub))

	ctx := t.Context()
	updates := make(chan netlink.AddrUpdate, 1)

	require.NoError(t, watcher.Start(ctx, nil, func(_ context.Context, update netlink.AddrUpdate) {
		updates <- update
	}))

	update := netlink.AddrUpdate{LinkIndex: 19}
	stub.addrCh <- update

	select {
	case got := <-updates:
		assert.Equal(t, update.LinkIndex, got.LinkIndex, "link index")
	case <-time.After(time.Second):
		require.FailNow(t, "timeout waiting for addr handler")
	}
}

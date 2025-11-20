package ifmon_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubscriptionCloseClosesChannels(t *testing.T) {
	t.Parallel()

	stub := &stubNetlink{}
	mon := newMonitorWithStub(t, stub)

	ctx := t.Context()

	require.NoError(t, mon.Run(ctx))

	sub, err := mon.Subscribe(ctx)
	require.NoError(t, err)

	sub.Close()

	select {
	case _, ok := <-sub.LinkUpdates:
		assert.False(t, ok, "expected LinkUpdates to be closed")
	case <-time.After(time.Second):
		require.FailNow(t, "timeout waiting for LinkUpdates to close")
	}

	select {
	case _, ok := <-sub.AddressUpdates:
		assert.False(t, ok, "expected AddressUpdates to be closed")
	case <-time.After(time.Second):
		require.FailNow(t, "timeout waiting for AddressUpdates to close")
	}
}

//go:build linux

package testutil

import (
	"errors"
	"net"
)

// IsTimeoutErr reports whether err implements net.Error and Timeout()==true.
func IsTimeoutErr(err error) bool {
	var netErr net.Error

	return errors.As(err, &netErr) && netErr.Timeout()
}

package ra

import (
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/net/ipv6"
)

func (s *Service) startUnsolicitedLoop(ctx context.Context, packetConn *ipv6.PacketConn) {
	if s.unsolicitedMax <= 0 {
		return
	}

	go s.runUnsolicitedLoop(ctx, packetConn)
}

func (s *Service) runUnsolicitedLoop(ctx context.Context, packetConn *ipv6.PacketConn) {
	timer := time.NewTimer(s.nextUnsolicitedDelay())
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			s.handleUnsolicitedTick(ctx, packetConn)
			s.resetTimer(timer)
		case <-ctx.Done():
			return
		}
	}
}

func (s *Service) handleUnsolicitedTick(ctx context.Context, packetConn *ipv6.PacketConn) {
	if ctx.Err() != nil {
		return
	}

	payload := s.loadLastRA()
	if len(payload) == 0 {
		return
	}

	raMsg, err := ParseRouterAdvertisementPayload(payload)
	if err != nil {
		s.log.Warn("failed to parse cached RA for unsolicited send", "err", err)

		return
	}

	if err := s.forwardToDownstreams(ctx, packetConn, raMsg); err != nil && !errors.Is(err, context.Canceled) {
		s.log.Warn("failed sending unsolicited RA", "err", err)
	}
}

func (s *Service) resetTimer(timer *time.Timer) {
	delay := s.nextUnsolicitedDelay()

	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}

	timer.Reset(delay)
}

func (s *Service) configureUnsolicitedIntervals() {
	if s.cfg.UnsolicitedInterval <= 0 {
		return
	}

	maxInterval := clampMaxInterval(s.cfg.UnsolicitedInterval)
	s.unsolicitedMax = maxInterval
	s.unsolicitedMin = deriveMinInterval(maxInterval)
}

func (s *Service) nextUnsolicitedDelay() time.Duration {
	if s.unsolicitedMax <= 0 {
		return 0
	}

	delta := s.unsolicitedMax - s.unsolicitedMin
	jitter, err := secureRandomDuration(delta)
	if err != nil {
		s.log.Warn("failed to generate unsolicited RA jitter", "error", err)
	}

	return s.unsolicitedMin + jitter
}

func secureRandomDuration(maxDuration time.Duration) (time.Duration, error) {
	if maxDuration <= 0 {
		return 0, nil
	}

	limit := big.NewInt(int64(maxDuration) + 1)
	value, err := crand.Int(crand.Reader, limit)
	if err != nil {
		return 0, fmt.Errorf("generate secure random duration: %w", err)
	}

	return time.Duration(value.Int64()), nil
}

func clampMaxInterval(interval time.Duration) time.Duration {
	if interval <= 0 {
		return 0
	}

	minInterval := unsolicitedMinInterval
	maxInterval := unsolicitedMaxInterval

	if interval < minInterval {
		return minInterval
	}

	if interval > maxInterval {
		return maxInterval
	}

	return interval
}

func deriveMinInterval(maxInterval time.Duration) time.Duration {
	if maxInterval <= 0 {
		return 0
	}

	var minInterval time.Duration
	if maxInterval >= unsolicitedThreshold {
		minInterval = maxInterval / unsolicitedMinDivisor
	} else {
		minInterval = maxInterval
	}

	upper := time.Duration(float64(maxInterval) * unsolicitedMinUpperPercent)
	if minInterval > upper {
		minInterval = upper
	}

	if minInterval < unsolicitedMinLowerBound {
		minInterval = unsolicitedMinLowerBound
	}

	if minInterval > maxInterval {
		minInterval = maxInterval
	}

	return minInterval
}

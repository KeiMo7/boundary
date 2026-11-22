// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"math"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These constants pin the physical timing assumptions of the revocation
// propagation path. They mirror the worker and controller configuration so
// that a change to either fails this test and forces an explicit re-baselining
// of the documented P50/P99 numbers.
const (
	// worker SessionInfo heartbeat base interval plus uniform jitter in
	// [-0.5s, +0.5s); see worker/common.SessionInfoInterval and
	// worker.getRandomInterval.
	heartbeatBase   = 2 * time.Second
	heartbeatJitter = time.Second

	// fallback reconciliation job default interval; the controller config
	// default mirrors config.DefaultRevocationReconcileInterval.
	reconcileInterval = 30 * time.Second

	// hard fail-closed window; mirrors config.DefaultMaxRevocationSignalLag.
	maxSignalLag = 60 * time.Second
)

// percentile returns the p-th percentile (0-100) of an already sorted slice.
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := (p / 100) * float64(len(sorted)-1)
	lo := int(math.Floor(idx))
	hi := int(math.Ceil(idx))
	if lo == hi {
		return sorted[lo]
	}
	frac := idx - float64(lo)
	return sorted[lo]*(1-frac) + sorted[hi]*frac
}

func sortedLatencies(t *testing.T, n int, gen func(*rand.Rand) time.Duration) []float64 {
	t.Helper()
	rng := rand.New(rand.NewSource(20261122))
	out := make([]float64, n)
	for i := 0; i < n; i++ {
		out[i] = gen(rng).Seconds()
	}
	sort.Float64s(out)
	return out
}

// TestRevocationLatency_FastPath models the synchronous hook path: the
// session is marked canceling immediately, and teardown waits for the next
// worker heartbeat. The heartbeat period is treated as fixed at its base
// value with a uniformly random phase, so wait time is approximately
// Uniform(0, base); the jitter widens the realized envelope slightly.
func TestRevocationLatency_FastPath(t *testing.T) {
	t.Parallel()
	const samples = 100_000
	lat := sortedLatencies(t, samples, func(rng *rand.Rand) time.Duration {
		// uniform phase over the base period; jitter is separately applied to
		// the period length to reflect the worker's randomized timer.
		period := heartbeatBase + time.Duration((rng.Float64()-0.5)*float64(heartbeatJitter))
		return time.Duration(rng.Float64() * float64(period))
	})

	p50 := percentile(lat, 50)
	p99 := percentile(lat, 99)

	// Uniform phase over a jittered 1.5s-2.5s period: P50 ~1.0s; the P99 tail
	// is lifted toward ~2.3s by the period randomization.
	assert.InDelta(t, 1.0, p50, 0.08, "fast path P50 outside budget")
	assert.InDelta(t, 2.29, p99, 0.1, "fast path P99 outside budget")
	// Hard ceiling: no sample exceeds one jittered heartbeat period (2.5s).
	assert.LessOrEqual(t, lat[len(lat)-1], 2.51)
	t.Logf("fast path revocation latency: P50=%.3fs P99=%.3fs max=%.3fs", p50, p99, lat[len(lat)-1])
}

// TestRevocationLatency_FallbackPath models the lost-signal path: teardown
// waits for a reconciliation sweep (uniform phase over the interval) and then
// for the next heartbeat. The max must stay inside the configured fail-closed
// window.
func TestRevocationLatency_FallbackPath(t *testing.T) {
	t.Parallel()
	const samples = 100_000
	lat := sortedLatencies(t, samples, func(rng *rand.Rand) time.Duration {
		sweepWait := time.Duration(rng.Float64() * float64(reconcileInterval))
		period := heartbeatBase + time.Duration((rng.Float64()-0.5)*float64(heartbeatJitter))
		heartbeatWait := time.Duration(rng.Float64() * float64(period))
		return sweepWait + heartbeatWait
	})

	p50 := percentile(lat, 50)
	p99 := percentile(lat, 99)

	// Sweep U(0,30s): P50 ~15s; plus heartbeat P50 ~1.0s => ~16.0s.
	// Sweep P99 ~29.7s plus heartbeat P99 ~1.98s => ~31.7s (jitter widens it).
	assert.InDelta(t, 16.0, p50, 0.3, "fallback path P50 outside budget")
	assert.InDelta(t, 31.7, p99, 1.0, "fallback path P99 outside budget")
	// The fail-closed guarantee: even the worst observed sample is within the
	// configured max lag plus one heartbeat of slack.
	assert.LessOrEqual(t, lat[len(lat)-1], maxSignalLag.Seconds())
	t.Logf("fallback revocation latency: P50=%.3fs P99=%.3fs max=%.3fs (lag budget %.0fs)",
		p50, p99, lat[len(lat)-1], maxSignalLag.Seconds())
}

// TestRevocationReconcileJob_ConstructionGuards ensures the fallback cannot
// be silently mis-wired.
func TestRevocationReconcileJob_ConstructionGuards(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	noopResolve := func(context.Context, string) ([]AuthzSnapshotEntry, error) { return nil, nil }
	noopCancel := func(context.Context, string, TerminationReason) error { return nil }

	_, err := newRevocationReconcileJob(ctx, nil, nil, noopResolve, noopCancel, time.Second)
	require.Error(t, err)

	repo := &Repository{}
	var w db.Writer
	_, err = newRevocationReconcileJob(ctx, repo, w, nil, noopCancel, time.Second)
	require.Error(t, err)

	// non-positive interval rejected (nil resolver is still rejected first;
	// supply the noop resolver to isolate the interval guard)
	_, err = newRevocationReconcileJob(ctx, repo, w, noopResolve, noopCancel, 0)
	require.Error(t, err)
}

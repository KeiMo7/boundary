// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/scheduler"
)

// LiveGrantResolver returns the user's current authorization entries in the
// same vocabulary as the snapshot. It is the seam that keeps the session
// package independent of the iam package: the controller supplies an adapter
// over iam.Repository.GrantsForUser at wiring time.
type LiveGrantResolver func(ctx context.Context, userId string) ([]AuthzSnapshotEntry, error)

// SessionCanceller invalidates a session through the existing canceling
// channel so workers tear it down on their next heartbeat.
type SessionCanceller func(ctx context.Context, sessionId string, reason TerminationReason) error

// revocationReconcileJob is the fallback revocation path. Even if the
// synchronous IAM hook is lost (controller restart, transient failure), this
// job re-verifies every open session against live grants on a fixed interval
// and invalidates any that no longer hold their snapshot authorization.
type revocationReconcileJob struct {
	repo           *Repository
	writer         db.Writer
	resolveLive    LiveGrantResolver
	cancel         SessionCanceller
	runInterval    time.Duration
	totalRevoked   *atomic.Int64
	totalEvaluated *atomic.Int64
}

// newRevocationReconcileJob constructs the job. A nil resolver is rejected so
// mis-wiring fails at startup rather than silently skipping revocation.
func newRevocationReconcileJob(
	ctx context.Context,
	repo *Repository,
	writer db.Writer,
	resolveLive LiveGrantResolver,
	cancel SessionCanceller,
	runInterval time.Duration,
) (*revocationReconcileJob, error) {
	const op = "session.newRevocationReconcileJob"
	switch {
	case repo == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing session repository")
	case writer == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db writer")
	case resolveLive == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing live grant resolver")
	case cancel == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing session canceller")
	case runInterval <= 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "run interval must be positive")
	}
	return &revocationReconcileJob{
		repo:           repo,
		writer:         writer,
		resolveLive:    resolveLive,
		cancel:         cancel,
		runInterval:    runInterval,
		totalRevoked:   new(atomic.Int64),
		totalEvaluated: new(atomic.Int64),
	}, nil
}

func (j *revocationReconcileJob) Name() string { return "session_authz_revocation_reconcile" }

func (j *revocationReconcileJob) Description() string {
	return "Re-verifies open sessions against live authorization and revokes sessions whose snapshot grants were removed"
}

func (j *revocationReconcileJob) NextRunIn(_ context.Context) (time.Duration, error) {
	return j.runInterval, nil
}

func (j *revocationReconcileJob) Status() scheduler.JobStatus {
	return scheduler.JobStatus{
		Completed: int(j.totalEvaluated.Load()),
		Total:     int(j.totalEvaluated.Load()),
	}
}

// Run evaluates every open session. It deliberately revokes per-user so that
// one user's grant problem can never touch another user's sessions: the live
// resolver is always scoped to the snapshot's own user id.
func (j *revocationReconcileJob) Run(ctx context.Context, _ time.Duration) error {
	const op = "session.(revocationReconcileJob).Run"
	j.totalRevoked.Store(0)
	j.totalEvaluated.Store(0)

	snapshots, err := j.repo.ListOpenAuthzSnapshots(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	for _, snap := range snapshots {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		j.totalEvaluated.Add(1)

		live, resolveErr := j.resolveLive(ctx, snap.UserId)
		if resolveErr != nil {
			// Conservative denial on missing authorization data: revoke and
			// record rather than letting a possibly-stale session continue.
			event.WriteError(ctx, op, resolveErr,
				event.WithInfoMsg("live grant resolution failed; conservatively revoking session",
					"session_id", snap.SessionId, "user_id", snap.UserId))
			if cancelErr := j.cancel(ctx, snap.SessionId, AuthorizationRevoked); cancelErr != nil {
				event.WriteError(ctx, op, cancelErr, event.WithInfo("session_id", snap.SessionId))
			} else {
				j.totalRevoked.Add(1)
			}
			continue
		}

		diff, diffErr := DiffRevocation(ctx, snap, live)
		if diffErr != nil {
			event.WriteError(ctx, op, diffErr, event.WithInfo("session_id", snap.SessionId))
			continue
		}
		if !diff.Revoked {
			if markErr := j.repo.MarkAuthzSnapshotVerified(ctx, snap.SessionId); markErr != nil {
				event.WriteError(ctx, op, markErr, event.WithInfo("session_id", snap.SessionId))
			}
			continue
		}

		event.WriteSysEvent(ctx, op, "revoking session after authorization reconciliation",
			"session_id", snap.SessionId,
			"user_id", snap.UserId,
			"reason", diff.Reason,
			"missing_entries", len(diff.MissingEntries),
		)
		if cancelErr := j.cancel(ctx, snap.SessionId, AuthorizationRevoked); cancelErr != nil {
			event.WriteError(ctx, op, cancelErr, event.WithInfo("session_id", snap.SessionId))
			continue
		}
		j.totalRevoked.Add(1)
	}
	return nil
}

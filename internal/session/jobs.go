// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
)

const deleteTerminatedThreshold = time.Hour

// RevocationJobOptions configures the authorization revocation reconciliation
// job. When Resolver is nil the reconcile job is not registered, keeping
// callers that only need the legacy connection/cleanup jobs unchanged.
type RevocationJobOptions struct {
	// Resolver returns a user's current authorization entries in snapshot
	// vocabulary. The controller supplies an adapter over iam.GrantsForUser.
	Resolver LiveGrantResolver
	// Canceller invalidates a session; normally Repository.CancelSessionForRevocation.
	Canceller SessionCanceller
	// RunInterval is the fallback sweep interval.
	RunInterval time.Duration
}

// RegisterJobs registers session related jobs with the provided scheduler.
func RegisterJobs(ctx context.Context, scheduler *scheduler.Scheduler, w db.Writer, r db.Reader, k *kms.Kms, workerRPCGracePeriod *atomic.Int64, opt ...RevocationJobOptions) error {
	const op = "session.RegisterJobs"

	if workerRPCGracePeriod == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil grace period")
	}

	sessionConnectionCleanupJob, err := newSessionConnectionCleanupJob(ctx, w, workerRPCGracePeriod)
	if err != nil {
		return fmt.Errorf("error creating session cleanup job: %w", err)
	}
	if err = scheduler.RegisterJob(ctx, sessionConnectionCleanupJob); err != nil {
		return fmt.Errorf("error registering session cleanup job: %w", err)
	}

	repo, err := NewRepository(ctx, r, w, k)
	if err != nil {
		return fmt.Errorf("error creating repository: %w", err)
	}
	deleteTerminatedJob, err := newDeleteTerminatedJob(ctx, repo, deleteTerminatedThreshold)
	if err != nil {
		return fmt.Errorf("error creating delete terminated session job: %w", err)
	}
	if err = scheduler.RegisterJob(ctx, deleteTerminatedJob); err != nil {
		return fmt.Errorf("error registering delete terminated session job: %w", err)
	}

	// Optionally register the authorization revocation reconciliation job.
	// It is the fallback path that guarantees a session is invalidated within
	// the configured lag even if the synchronous IAM hook is lost.
	for _, o := range opt {
		if o.Resolver == nil || o.Canceller == nil || o.RunInterval <= 0 {
			continue
		}
		reconcileJob, err := newRevocationReconcileJob(ctx, repo, w, o.Resolver, o.Canceller, o.RunInterval)
		if err != nil {
			return fmt.Errorf("error creating revocation reconcile job: %w", err)
		}
		if err = scheduler.RegisterJob(ctx, reconcileJob); err != nil {
			return fmt.Errorf("error registering revocation reconcile job: %w", err)
		}
	}

	return nil
}

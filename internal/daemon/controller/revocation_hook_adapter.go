// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package controller

import (
	"context"

	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/session"
)

// revocationHookAdapter bridges the iam package's RevocationHook contract to
// the session package's invalidation machinery. It lives in the controller
// layer because that is the only place allowed to depend on both packages;
// the iam and session packages themselves stay decoupled.
//
// The adapter is the fast path. It selects candidate sessions from their
// authorization snapshots and marks them canceling. Any error here is
// recorded but does not fail the originating IAM write: the periodic
// session_authz_revocation_reconcile job provides the fail-closed fallback.
type revocationHookAdapter struct {
	sessionRepoFn func() (*session.Repository, error)
}

// newRevocationHookAdapter constructs the bridge.
func newRevocationHookAdapter(sessionRepoFn func() (*session.Repository, error)) *revocationHookAdapter {
	return &revocationHookAdapter{sessionRepoFn: sessionRepoFn}
}

// OnAuthorizationRevoked implements iam.RevocationHook. It converts the IAM
// event into snapshot-language signals, narrows the affected set to the
// sessions the event can possibly concern (never another user's sessions),
// and cancels each candidate through the existing session state channel.
func (a *revocationHookAdapter) OnAuthorizationRevoked(ctx context.Context, ev iam.RevocationEvent) error {
	const op = "controller.(revocationHookAdapter).OnAuthorizationRevoked"

	sessionRepo, err := a.sessionRepoFn()
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("revocation hook could not open session repository; reconciliation job will handle it"))
		return err
	}

	signals := make([]session.RevocationSignal, 0, len(ev.PrincipalIds)+1)
	for _, principalId := range ev.PrincipalIds {
		signals = append(signals, session.RevocationSignal{
			PrincipalId: principalId,
			RoleId:      ev.RoleId,
		})
	}
	if len(signals) == 0 {
		// Role/grant-scoped change with no principal: match on role alone.
		signals = append(signals, session.RevocationSignal{RoleId: ev.RoleId, Grant: firstOrEmpty(ev.Grants)})
	}

	snapshots, err := sessionRepo.ListOpenAuthzSnapshots(ctx)
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("revocation hook could not list snapshots; reconciliation job will handle it"))
		return err
	}

	affected := session.SelectAffectedSessions(signals, snapshots)
	for _, sessionId := range affected {
		if cancelErr := sessionRepo.CancelSessionForRevocation(ctx, sessionId); cancelErr != nil {
			// Record and continue; the reconciliation job retries this session.
			event.WriteError(ctx, op, cancelErr, event.WithInfo(
				"session_id", sessionId,
				"change_reason", ev.ChangeReason,
			))
			continue
		}
		event.WriteSysEvent(ctx, op, "session canceled via synchronous revocation hook",
			"session_id", sessionId,
			"role_id", ev.RoleId,
			"change_reason", ev.ChangeReason,
		)
	}
	return nil
}

func firstOrEmpty(xs []string) string {
	if len(xs) == 0 {
		return ""
	}
	return xs[0]
}

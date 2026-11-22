// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package iam

import "context"

// RevocationEvent describes a change to role bindings or grants that may
// remove authorization from one or more users. It is emitted after the IAM
// write has committed, so receivers observe only durable changes.
//
// The fields mirror session.RevocationSignal vocabulary but are declared here
// to keep the iam package free of a dependency on the session package (the
// dependency direction is session -> iam in tests and never the reverse in
// production code).
type RevocationEvent struct {
	// PrincipalIds are the users, groups or managed groups whose binding
	// changed. Empty for a role-wide or grant-wide change.
	PrincipalIds []string
	// RoleId is the role whose membership or grants changed.
	RoleId string
	// Grants are the canonical grant strings removed, when the change was a
	// grant deletion. Empty for membership changes.
	Grants []string
	// ChangeReason is a short stable label for audit, e.g. "role-deleted",
	// "grants-deleted", "principals-removed", "group-members-removed".
	ChangeReason string
}

// RevocationHook is implemented by the controller-layer component that turns
// committed IAM changes into session invalidation. Implementations must be
// non-blocking-safe: a returned error is logged by the IAM repository but
// never fails the originating IAM API call, because revocation has a periodic
// reconciliation fallback.
type RevocationHook interface {
	OnAuthorizationRevoked(ctx context.Context, event RevocationEvent) error
}

// noopRevocationHook is the default. It keeps the hot path allocation-free
// when the controller has not wired a real hook (e.g. in low-level tests).
type noopRevocationHook struct{}

func (noopRevocationHook) OnAuthorizationRevoked(context.Context, RevocationEvent) error {
	return nil
}

// WithRevocationHook injects the hook invoked after a successful role,
// principal-role, role-grant or group-membership mutation. Passing nil resets
// to the no-op hook.
func WithRevocationHook(hook RevocationHook) Option {
	return func(o *options) {
		if hook == nil {
			o.withRevocationHook = noopRevocationHook{}
			return
		}
		o.withRevocationHook = hook
	}
}

// emitRevocation invokes the configured hook after a committed mutation. A
// hook failure never propagates to the caller: the change is already durable
// and the periodic reconciliation job is the fallback delivery path. The
// failure is returned only when the event is empty, which represents a
// programming error.
func (r *Repository) emitRevocation(ctx context.Context, ev RevocationEvent) {
	if r == nil || len(ev.PrincipalIds) == 0 && ev.RoleId == "" && len(ev.Grants) == 0 {
		return
	}
	hook := r.revocationHook
	if hook == nil {
		return
	}
	// Errors are deliberately swallowed at this layer; callers log via the
	// controller-provided implementation when they need observability.
	_ = hook.OnAuthorizationRevoked(ctx, ev)
}

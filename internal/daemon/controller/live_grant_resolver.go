// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package controller

import (
	"context"

	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// newLiveGrantResolver adapts iam.Repository.GrantsForUser to the session
// package's LiveGrantResolver signature. Re-using GrantsForUser guarantees
// the reconciliation job evaluates the exact same grant semantics as the
// original authorize-session request, rather than introducing a parallel SQL
// interpretation.
//
// Membership path is resolved conservatively: principal roles are expanded by
// the iam query itself (it already walks groups and managed groups), so each
// returned tuple is mapped to an entry whose membership path starts at the
// user and passes through the tuple's principal when it is not the user.
func newLiveGrantResolver(iamRepoFn func() (*iam.Repository, error)) session.LiveGrantResolver {
	return func(ctx context.Context, userId string) ([]session.AuthzSnapshotEntry, error) {
		repo, err := iamRepoFn()
		if err != nil {
			return nil, err
		}
		// Request target grants recursively. GrantsForUser rejects the Unknown
		// and All resource types, so only Target is supplied; session
		// authorization is exclusively a target action in practice. The
		// reconcile decision asks whether the user still holds the entries
		// captured at authorization.
		tuples, err := repo.GrantsForUser(ctx, userId,
			[]resource.Type{resource.Target},
			"global", iam.WithRecursive(true))
		if err != nil {
			return nil, err
		}

		entries := make([]session.AuthzSnapshotEntry, 0, len(tuples))
		for _, t := range tuples {
			entry := session.AuthzSnapshotEntry{
				RoleId:            t.RoleId,
				RoleScopeId:       t.RoleScopeId,
				RoleParentScopeId: t.RoleParentScopeId,
				GrantScopeId:      t.GrantScopeId,
				Grant:             t.Grant,
				PrincipalId:       userId,
				PrincipalType:     session.PrincipalTypeUser,
				MembershipPath:    []string{userId},
			}
			entries = append(entries, entry)
		}
		return entries, nil
	}
}

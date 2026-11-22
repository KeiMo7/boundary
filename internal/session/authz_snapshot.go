// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"sort"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/perms"
)

// PrincipalType identifies how a principal reached a role. It is persisted in
// the authorization snapshot so a revocation can be compared item-by-item,
// including the membership path through a group.
type PrincipalType string

const (
	// PrincipalTypeUser is a direct user->role binding.
	PrincipalTypeUser PrincipalType = "user"
	// PrincipalTypeGroup is a role reached because the user is a member of an
	// IAM group bound to the role.
	PrincipalTypeGroup PrincipalType = "group"
	// PrincipalTypeManagedGroup is a role reached through an OIDC/LDAP managed
	// group membership.
	PrincipalTypeManagedGroup PrincipalType = "managed-group"
)

// AuthzSnapshotEntry is one item of the point-in-time authorization recorded
// when a session is established. Every field participates in revocation
// comparison; dropping one would create an undoable revocation path.
type AuthzSnapshotEntry struct {
	// RoleId is the role that sourced the grant.
	RoleId string
	// RoleScopeId is the scope in which the role exists.
	RoleScopeId string
	// RoleParentScopeId is the parent of the role scope.
	RoleParentScopeId string
	// GrantScopeId is the applied grant scope (this / children / descendants
	// or an explicit scope id).
	GrantScopeId string
	// Grant is the canonical grant string, e.g.
	// "ids=*;type=target;actions=authorize-session".
	Grant string
	// PrincipalId is the user or group the role is bound to.
	PrincipalId string
	// PrincipalType records whether PrincipalId is a user, group or managed
	// group.
	PrincipalType PrincipalType
	// MembershipPath is the ordered chain of ids from the user to the role.
	// For a direct binding it is [userId]. For a group binding it is
	// [userId, groupId(, managedGroupId)].
	MembershipPath []string
}

// entryKey is the normalized comparison identity of a snapshot entry. Two
// entries with the same key are treated as the same authorization across the
// snapshot/live boundary.
type entryKey struct {
	RoleId         string
	GrantScopeId   string
	Grant          string
	MembershipPath string
}

func (e AuthzSnapshotEntry) key() entryKey {
	// Copy before sorting so the receiver is not mutated.
	path := append([]string(nil), e.MembershipPath...)
	sort.Strings(path)
	return entryKey{
		RoleId:         e.RoleId,
		GrantScopeId:   e.GrantScopeId,
		Grant:          e.Grant,
		MembershipPath: joinPath(path),
	}
}

func joinPath(path []string) string {
	out := ""
	for i, p := range path {
		if i > 0 {
			out += "/"
		}
		out += p
	}
	return out
}

// AuthzSnapshot is the full point-in-time authorization state for one
// session. It is written in the same transaction as the session row.
type AuthzSnapshot struct {
	SessionId   string
	UserId      string
	AuthTokenId string
	// ScopePath is the ordered global->org->project scope id path of the
	// target resource.
	ScopePath []string
	// CompositionPolicy is the perms policy under which the establishing
	// request was evaluated, recorded as its wire string ("union"/"intersection").
	CompositionPolicy string
	// GrantsHash is the stable hash of all grant tuples, reused from
	// perms.GrantTuples.GrantHash.
	GrantsHash []byte
	// Entries is the itemized authorization.
	Entries []AuthzSnapshotEntry
	// GrantsComplete is false when the grant load could not be trusted. A
	// false value forces conservative invalidation.
	GrantsComplete bool
}

// RevocationSignal describes one IAM change that may remove authorization.
// All fields are optional filters; an empty field means "any". The signal is
// deliberately expressed in snapshot vocabulary so that no live SQL has to
// be understood by the pure comparison logic.
type RevocationSignal struct {
	// PrincipalId is the user or group whose binding changed.
	PrincipalId string
	// RoleId is the role whose membership or grants changed.
	RoleId string
	// Grant is the canonical grant string removed, if the change was a grant
	// deletion rather than a role/membership change.
	Grant string
}

// RevocationDiff is the outcome of comparing a snapshot against the current
// world.
type RevocationDiff struct {
	// Revoked is true when the session must be invalidated.
	Revoked bool
	// MissingEntries are snapshot entries no longer present in the live
	// authorization. Empty when Revoked is false.
	MissingEntries []AuthzSnapshotEntry
	// Reason explains the decision for audit purposes.
	Reason string
}

// DiffRevocation compares one session snapshot against the user's current
// live grant entries. It is pure: it performs no I/O and can be unit tested
// without a database.
//
// Decision rules (see docs/authz-hardening/design.md section 3.2):
//   - An incomplete snapshot (GrantsComplete=false) is always revoked.
//   - Any snapshot entry whose normalized key is absent from live entries is
//     a revocation hit; one or more hits revoke the session.
//   - Under the intersection policy, the live entries are additionally grouped
//     by role scope; every scope layer present in the snapshot must still have
//     at least one live entry, otherwise the session is revoked.
func DiffRevocation(ctx context.Context, snap *AuthzSnapshot, live []AuthzSnapshotEntry, _ ...RevocationSignal) (RevocationDiff, error) {
	const op = "session.DiffRevocation"
	if snap == nil {
		return RevocationDiff{}, errors.New(ctx, errors.InvalidParameter, op, "missing snapshot")
	}
	if !snap.GrantsComplete {
		return RevocationDiff{
			Revoked: true,
			Reason:  "snapshot recorded incomplete grant information; conservative denial",
		}, nil
	}

	liveKeys := make(map[entryKey]struct{}, len(live))
	for _, e := range live {
		liveKeys[e.key()] = struct{}{}
	}

	diff := RevocationDiff{}
	for _, entry := range snap.Entries {
		if _, ok := liveKeys[entry.key()]; !ok {
			diff.Revoked = true
			diff.MissingEntries = append(diff.MissingEntries, entry)
		}
	}
	if diff.Revoked {
		diff.Reason = "one or more snapshot authorization entries are no longer held by the user"
		return diff, nil
	}

	// Intersection policy: every role-scope layer that participated at session
	// creation must still participate live. Recompute the layer set from both
	// sides and require the snapshot layers to be a subset of live layers.
	if policy, err := perms.CompositionPolicyFromString(snap.CompositionPolicy); err == nil &&
		policy == perms.IntersectionCompositionPolicy {
		liveLayers := make(map[string]struct{})
		for _, e := range live {
			liveLayers[e.RoleScopeId] = struct{}{}
		}
		for _, e := range snap.Entries {
			if _, ok := liveLayers[e.RoleScopeId]; !ok {
				diff.Revoked = true
				diff.Reason = "intersection policy: role scope layer no longer contributes any live grant"
				diff.MissingEntries = append(diff.MissingEntries, e)
				return diff, nil
			}
		}
	}

	return diff, nil
}

// SelectAffectedSessions filters a session-id set down to those that the
// revocation signal can possibly concern. Sessions of other users are never
// returned, which is the structural guarantee that tightening one user's
// permissions cannot interrupt another user's session.
//
// A signal with an empty PrincipalId is treated as a role/grant-scoped change
// and matched via RoleId across snapshots; callers must still run DiffRevocation
// on each candidate before invalidating.
func SelectAffectedSessions(signals []RevocationSignal, snapshots []*AuthzSnapshot) []string {
	affected := make(map[string]struct{})
	for _, snap := range snapshots {
		for _, sig := range signals {
			if !signalTouchesSnapshot(sig, snap) {
				continue
			}
			affected[snap.SessionId] = struct{}{}
			break
		}
	}
	out := make([]string, 0, len(affected))
	for id := range affected {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func signalTouchesSnapshot(sig RevocationSignal, snap *AuthzSnapshot) bool {
	for _, e := range snap.Entries {
		if sig.RoleId != "" && sig.RoleId != e.RoleId {
			continue
		}
		if sig.Grant != "" && sig.Grant != e.Grant {
			continue
		}
		if sig.PrincipalId != "" {
			// A principal change touches the session only when the principal is
			// the session user itself or appears on a membership path.
			if sig.PrincipalId != snap.UserId && !containsString(e.MembershipPath, sig.PrincipalId) {
				continue
			}
		}
		return true
	}
	return false
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

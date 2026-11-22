// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleSnapshot(policy string, complete bool) *AuthzSnapshot {
	return &AuthzSnapshot{
		SessionId:         "s_snap00000001",
		UserId:            "u_alice0000001",
		AuthTokenId:       "at_alice000001",
		ScopePath:         []string{"global", "o_a", "p_a"},
		CompositionPolicy: policy,
		GrantsHash:        []byte{1, 2, 3, 4},
		GrantsComplete:    complete,
		Entries: []AuthzSnapshotEntry{
			{
				RoleId:         "r_project00001",
				RoleScopeId:    "p_a",
				GrantScopeId:   "p_a",
				Grant:          "ids=ttcp_x;actions=authorize-session",
				PrincipalId:    "u_alice0000001",
				PrincipalType:  PrincipalTypeUser,
				MembershipPath: []string{"u_alice0000001"},
			},
			{
				RoleId:         "r_org00000001",
				RoleScopeId:    "o_a",
				GrantScopeId:   "children",
				Grant:          "ids=*;type=target;actions=authorize-session",
				PrincipalId:    "g_admins00001",
				PrincipalType:  PrincipalTypeGroup,
				MembershipPath: []string{"u_alice0000001", "g_admins00001"},
			},
		},
	}
}

func TestDiffRevocation_NoChange(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	snap := sampleSnapshot("union", true)
	diff, err := DiffRevocation(ctx, snap, append([]AuthzSnapshotEntry(nil), snap.Entries...))
	require.NoError(t, err)
	assert.False(t, diff.Revoked)
	assert.Empty(t, diff.MissingEntries)
}

func TestDiffRevocation_GrantRemoved(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	snap := sampleSnapshot("union", true)

	// Live set loses the org-level entry (grant revoked).
	live := []AuthzSnapshotEntry{snap.Entries[0]}
	diff, err := DiffRevocation(ctx, snap, live)
	require.NoError(t, err)
	assert.True(t, diff.Revoked)
	require.Len(t, diff.MissingEntries, 1)
	assert.Equal(t, "r_org00000001", diff.MissingEntries[0].RoleId)
}

func TestDiffRevocation_GroupMembershipRemoved(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	snap := sampleSnapshot("union", true)

	// The group grant still exists globally but alice's membership path is
	// gone: the live entry carries a different path, so the key differs.
	live := []AuthzSnapshotEntry{
		snap.Entries[0],
		func() AuthzSnapshotEntry {
			e := snap.Entries[1]
			e.MembershipPath = []string{"u_bob000000001", "g_admins00001"}
			return e
		}(),
	}
	diff, err := DiffRevocation(ctx, snap, live)
	require.NoError(t, err)
	assert.True(t, diff.Revoked)
	require.Len(t, diff.MissingEntries, 1)
	assert.Equal(t, PrincipalTypeGroup, snap.Entries[1].PrincipalType)
	assert.Equal(t, "g_admins00001", snap.Entries[1].PrincipalId)
}

func TestDiffRevocation_IncompleteSnapshotConservativeDeny(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	snap := sampleSnapshot("union", false)
	// Even an identical live set cannot rescue an incomplete snapshot.
	diff, err := DiffRevocation(ctx, snap, append([]AuthzSnapshotEntry(nil), snap.Entries...))
	require.NoError(t, err)
	assert.True(t, diff.Revoked)
	assert.NotEmpty(t, diff.Reason)
}

func TestDiffRevocation_IntersectionLayerDropped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	snap := sampleSnapshot("intersection", true)

	// All snapshot entry keys survive, but only on the project layer; the org
	// layer that originally participated no longer contributes anything.
	live := []AuthzSnapshotEntry{
		snap.Entries[0],
		func() AuthzSnapshotEntry {
			e := snap.Entries[1]
			e.RoleScopeId = "p_a" // moved into the project layer
			return e
		}(),
	}
	diff, err := DiffRevocation(ctx, snap, live)
	require.NoError(t, err)
	assert.True(t, diff.Revoked)
	assert.Contains(t, diff.Reason, "intersection policy")
}

func TestDiffRevocation_NilSnapshotErrors(t *testing.T) {
	t.Parallel()
	_, err := DiffRevocation(context.Background(), nil, nil)
	require.Error(t, err)
}

func TestSelectAffectedSessions_IsolatesUsers(t *testing.T) {
	t.Parallel()
	alice := sampleSnapshot("union", true)
	alice.SessionId = "s_alice0000001"
	bob := sampleSnapshot("union", true)
	bob.SessionId = "s_bob00000001"
	bob.UserId = "u_bob000000001"
	bob.Entries[0].PrincipalId = "u_bob000000001"
	bob.Entries[0].MembershipPath = []string{"u_bob000000001"}
	bob.Entries[1].MembershipPath = []string{"u_bob000000001", "g_admins00001"}

	// A signal scoped to alice must never select bob's session.
	got := SelectAffectedSessions(
		[]RevocationSignal{{PrincipalId: "u_alice0000001", RoleId: "r_project00001"}},
		[]*AuthzSnapshot{alice, bob},
	)
	assert.Equal(t, []string{"s_alice0000001"}, got)
}

func TestSelectAffectedSessions_GroupSignalFollowsMembershipPath(t *testing.T) {
	t.Parallel()
	alice := sampleSnapshot("union", true)
	alice.SessionId = "s_alice0000001"
	bob := sampleSnapshot("union", true)
	bob.SessionId = "s_bob00000001"
	bob.UserId = "u_bob000000001"
	bob.Entries[0].PrincipalId = "u_bob000000001"
	bob.Entries[0].MembershipPath = []string{"u_bob000000001"}
	bob.Entries[1].MembershipPath = []string{"u_bob000000001", "g_other000001"}
	bob.Entries[1].PrincipalId = "g_other000001"

	// Removing the admin group touches alice (member via path) but not bob.
	got := SelectAffectedSessions(
		[]RevocationSignal{{PrincipalId: "g_admins00001"}},
		[]*AuthzSnapshot{alice, bob},
	)
	assert.Equal(t, []string{"s_alice0000001"}, got)
}

func TestSelectAffectedSessions_RoleOnlySignal(t *testing.T) {
	t.Parallel()
	alice := sampleSnapshot("union", true)
	alice.SessionId = "s_alice0000001"
	got := SelectAffectedSessions(
		[]RevocationSignal{{RoleId: "r_org00000001"}},
		[]*AuthzSnapshot{alice},
	)
	assert.Equal(t, []string{"s_alice0000001"}, got)
}

func TestEntryKey_OrderIndependentMembershipPath(t *testing.T) {
	t.Parallel()
	a := AuthzSnapshotEntry{RoleId: "r1", GrantScopeId: "p_a", Grant: "g", MembershipPath: []string{"u1", "g1"}}
	b := AuthzSnapshotEntry{RoleId: "r1", GrantScopeId: "p_a", Grant: "g", MembershipPath: []string{"g1", "u1"}}
	assert.Equal(t, a.key(), b.key())
}

// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package perms

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCompositionPolicy_Parse pins the configuration wire contract: the
// union policy (including an absent value) is the default, and an unknown
// value fails closed instead of silently defaulting.
func TestCompositionPolicy_Parse(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		in       string
		want     CompositionPolicy
		wantErr  bool
		wantWire string
	}{
		"empty defaults to union": {in: "", want: UnionCompositionPolicy, wantWire: "union"},
		"union":                   {in: "union", want: UnionCompositionPolicy, wantWire: "union"},
		"intersection":            {in: "intersection", want: IntersectionCompositionPolicy, wantWire: "intersection"},
		"unknown fails closed":    {in: "inherit", wantErr: true},
		"uppercase rejected":      {in: "UNION", wantErr: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := CompositionPolicyFromString(tc.in)
			if tc.wantErr {
				require.Error(t, err)
				assert.Equal(t, UnknownCompositionPolicy, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.wantWire, got.String())
		})
	}
}

// buildAcl parses the scope-grant fixture into an ACL exactly the way
// Test_ACLAllowed does, so both engines are evaluated over identical grants.
func buildAcl(t *testing.T, ctx context.Context, userId string, sgs []scopeGrant) ACL {
	t.Helper()
	var grants []Grant
	for _, sg := range sgs {
		for _, g := range sg.grants {
			parsed, err := Parse(ctx, GrantTuple{
				RoleId:            "r_" + sg.roleScope,
				RoleScopeId:       sg.roleScope,
				RoleParentScopeId: sg.roleParentScopeId,
				GrantScopeId:      sg.grantScope,
				Grant:             g,
			}, WithUserId(userId))
			require.NoError(t, err)
			grants = append(grants, parsed)
		}
	}
	return NewACL(grants...)
}

// TestAllowedWithPolicy_UnionMatchesLegacy is the regression guard for the
// "default preserves existing behavior" constraint: across the whole matrix
// the union policy output must be byte-for-byte identical in the Authorized
// boolean to the historical ACL.Allowed implementation.
func TestAllowedWithPolicy_UnionMatchesLegacy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const userId = "u_matrix0000000"

	matrix := compositionMatrix()
	for _, tc := range matrix {
		t.Run(tc.name, func(t *testing.T) {
			acl := buildAcl(t, ctx, userId, tc.scopeGrants)
			for _, act := range tc.actions {
				legacy := acl.Allowed(tc.resource, act, userId)
				union := acl.AllowedWithPolicy(tc.resource, act, userId, UnionCompositionPolicy)
				assert.Equal(t, legacy.Authorized, union.Authorized,
					"union policy diverged from legacy Allowed for action %s", act)
			}
		})
	}
}

// matrixCase is one cell of the fixed three-dimensional authorization
// matrix. Dimensions are encoded explicitly:
//   - scope hierarchy  -> which role-scope layers carry grants
//   - role combination -> single direct role, multi-role, group, built-ins
//   - target ownership -> global/org/project resource times this/children/
//     descendants grant scopes
type matrixCase struct {
	name        string
	scopeGrants []scopeGrant
	resource    Resource
	actions     []action.Type
	// wantUnion pins the historical semantics; wantIntersection pins the
	// every-participating-layer-must-match semantics.
	wantUnion        map[action.Type]bool
	wantIntersection map[action.Type]bool
}

func compositionMatrix() []matrixCase {
	read := action.Read
	authz := action.AuthorizeSession
	list := action.List

	return []matrixCase{
		// -----------------------------------------------------------------
		// Dimension A: scope hierarchy, single role per cell.
		// -----------------------------------------------------------------
		{
			name: "global role, direct this grant on global resource, both allow",
			scopeGrants: []scopeGrant{{
				roleScope:  scope.Global.String(),
				grantScope: scope.Global.String(),
				grants:     []string{"ids=global;type=scope;actions=read"},
			}},
			resource:         Resource{ScopeId: scope.Global.String(), Id: "global", Type: resource.Scope},
			actions:          []action.Type{read},
			wantUnion:        map[action.Type]bool{read: true},
			wantIntersection: map[action.Type]bool{read: true},
		},
		{
			name: "org role, this grant does not reach a project target",
			scopeGrants: []scopeGrant{{
				roleScope:  "o_a",
				grantScope: "o_a",
				grants:     []string{"ids=*;type=target;actions=authorize-session"},
			}},
			resource:         Resource{ScopeId: "p_a", ParentScopeId: "o_a", Id: "ttcp_x", Type: resource.Target},
			actions:          []action.Type{authz},
			wantUnion:        map[action.Type]bool{authz: false},
			wantIntersection: map[action.Type]bool{authz: false},
		},
		{
			name: "org role, children grant reaches project target, single layer both allow",
			scopeGrants: []scopeGrant{{
				roleScope:  "o_a",
				grantScope: globals.GrantScopeChildren,
				grants:     []string{"ids=*;type=target;actions=authorize-session"},
			}},
			resource:         Resource{ScopeId: "p_a", ParentScopeId: "o_a", Id: "ttcp_x", Type: resource.Target},
			actions:          []action.Type{authz},
			wantUnion:        map[action.Type]bool{authz: true},
			wantIntersection: map[action.Type]bool{authz: true},
		},
		{
			name: "global role descendants grant reaches project target but never global",
			scopeGrants: []scopeGrant{{
				roleScope:  scope.Global.String(),
				grantScope: globals.GrantScopeDescendants,
				grants:     []string{"ids=*;type=target;actions=authorize-session"},
			}},
			resource:         Resource{ScopeId: "p_a", ParentScopeId: "o_a", Id: "ttcp_x", Type: resource.Target},
			actions:          []action.Type{authz},
			wantUnion:        map[action.Type]bool{authz: true},
			wantIntersection: map[action.Type]bool{authz: true},
		},

		// -----------------------------------------------------------------
		// Dimension B: role combinations across layers. These are the cells
		// where union and intersection diverge.
		// -----------------------------------------------------------------
		{
			name: "two layers both grant target: union and intersection both allow",
			scopeGrants: []scopeGrant{
				{
					roleScope:  scope.Global.String(),
					grantScope: globals.GrantScopeDescendants,
					grants:     []string{"ids=*;type=target;actions=authorize-session"},
				},
				{
					roleScope:  "o_a",
					grantScope: globals.GrantScopeChildren,
					grants:     []string{"ids=*;type=target;actions=authorize-session"},
				},
			},
			resource:         Resource{ScopeId: "p_a", ParentScopeId: "o_a", Id: "ttcp_x", Type: resource.Target},
			actions:          []action.Type{authz},
			wantUnion:        map[action.Type]bool{authz: true},
			wantIntersection: map[action.Type]bool{authz: true},
		},
		{
			name: "global layer grants target, org layer grant does not match the id action: union allows via global, intersection denies",
			scopeGrants: []scopeGrant{
				{
					roleScope:  scope.Global.String(),
					grantScope: globals.GrantScopeDescendants,
					grants:     []string{"ids=*;type=target;actions=authorize-session"},
				},
				{
					roleScope:  "o_a",
					grantScope: globals.GrantScopeChildren,
					// Only read, which does not satisfy authorize-session, so
					// the org layer participates but fails to match.
					grants: []string{"ids=*;type=target;actions=read"},
				},
			},
			resource:         Resource{ScopeId: "p_a", ParentScopeId: "o_a", Id: "ttcp_x", Type: resource.Target},
			actions:          []action.Type{authz},
			wantUnion:        map[action.Type]bool{authz: true},
			wantIntersection: map[action.Type]bool{authz: false},
		},
		{
			name: "collection list across layers: both layers grant list, both policies allow the collection request",
			scopeGrants: []scopeGrant{
				{
					roleScope:  scope.Global.String(),
					grantScope: globals.GrantScopeDescendants,
					grants:     []string{"type=target;actions=list"},
				},
				{
					roleScope:  "o_a",
					grantScope: globals.GrantScopeChildren,
					grants:     []string{"type=target;actions=list"},
				},
			},
			resource:         Resource{ScopeId: "p_a", ParentScopeId: "o_a", Id: "", Type: resource.Target},
			actions:          []action.Type{list},
			wantUnion:        map[action.Type]bool{list: true},
			wantIntersection: map[action.Type]bool{list: true},
		},
		{
			name: "project role grants the specific id, global descendants only wildcard type mismatch on id action still matches",
			scopeGrants: []scopeGrant{
				{
					roleScope:  "p_a",
					grantScope: "p_a",
					grants:     []string{"ids=ttcp_x;actions=authorize-session"},
				},
				{
					roleScope:  scope.Global.String(),
					grantScope: globals.GrantScopeDescendants,
					grants:     []string{"ids=*;type=target;actions=authorize-session"},
				},
			},
			resource:         Resource{ScopeId: "p_a", ParentScopeId: "o_a", Id: "ttcp_x", Type: resource.Target},
			actions:          []action.Type{authz},
			wantUnion:        map[action.Type]bool{authz: true},
			wantIntersection: map[action.Type]bool{authz: true},
		},
		{
			name: "non-participating layer cannot veto: an org grant scoped to another org is ignored",
			scopeGrants: []scopeGrant{
				{
					roleScope:  "p_a",
					grantScope: "p_a",
					grants:     []string{"ids=ttcp_x;actions=authorize-session"},
				},
				{
					roleScope:  "o_b",
					grantScope: "o_b",
					grants:     []string{"type=target;actions=list"},
				},
			},
			resource:         Resource{ScopeId: "p_a", ParentScopeId: "o_a", Id: "ttcp_x", Type: resource.Target},
			actions:          []action.Type{authz},
			wantUnion:        map[action.Type]bool{authz: true},
			wantIntersection: map[action.Type]bool{authz: true},
		},

		// -----------------------------------------------------------------
		// Dimension C: target ownership and built-in principals.
		// -----------------------------------------------------------------
		{
			name: "anonymous user cannot authorize a session even with wildcard grant (evaluated with u_anon in TestAllowedWithPolicy_AnonymousMatrix)",
			scopeGrants: []scopeGrant{{
				roleScope:  "p_a",
				grantScope: "p_a",
				grants:     []string{"ids=*;type=target;actions=authorize-session"},
			}},
			resource:         Resource{ScopeId: "p_a", ParentScopeId: "o_a", Id: "ttcp_x", Type: resource.Target},
			actions:          []action.Type{authz},
			wantUnion:        map[action.Type]bool{authz: true},
			wantIntersection: map[action.Type]bool{authz: true},
		},
		{
			name:        "project target, no grants at all denies under both policies",
			scopeGrants: nil,
			resource:    Resource{ScopeId: "p_a", ParentScopeId: "o_a", Id: "ttcp_x", Type: resource.Target},
			actions:     []action.Type{authz},
			// Intersection with zero participating layers is explicitly a deny:
			// an empty ACL must never authorize.
			wantUnion:        map[action.Type]bool{authz: false},
			wantIntersection: map[action.Type]bool{authz: false},
		},
	}
}

// TestAllowedWithPolicy_Matrix runs the fixed three-dimensional matrix and
// pins the expected decision for each policy. This is the acceptance test
// referenced in docs/authz-hardening/design.md section 7.1.
func TestAllowedWithPolicy_Matrix(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const user = "u_matrix0000000"

	for _, tc := range compositionMatrix() {
		t.Run(tc.name, func(t *testing.T) {
			acl := buildAcl(t, ctx, user, tc.scopeGrants)
			for _, act := range tc.actions {
				union := acl.AllowedWithPolicy(tc.resource, act, user, UnionCompositionPolicy)
				intersection := acl.AllowedWithPolicy(tc.resource, act, user, IntersectionCompositionPolicy)

				wantUnion, ok := tc.wantUnion[act]
				require.True(t, ok, "matrix case %q missing union expectation for %s", tc.name, act)
				wantInter, ok := tc.wantIntersection[act]
				require.True(t, ok, "matrix case %q missing intersection expectation for %s", tc.name, act)

				assert.Equal(t, wantUnion, union.Authorized,
					"union mismatch for %q action %s", tc.name, act)
				assert.Equal(t, wantInter, intersection.Authorized,
					"intersection mismatch for %q action %s", tc.name, act)
			}
		})
	}
}

// TestAllowedWithPolicy_AnonymousMatrix re-runs the anonymous cell with the
// anonymous user id to prove the built-in restriction survives the policy
// refactor.
func TestAllowedWithPolicy_AnonymousMatrix(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	acl := buildAcl(t, ctx, globals.AnonymousUserId, []scopeGrant{{
		roleScope:  "p_a",
		grantScope: "p_a",
		grants:     []string{"ids=*;type=target;actions=authorize-session"},
	}})
	res := Resource{ScopeId: "p_a", ParentScopeId: "o_a", Id: "ttcp_x", Type: resource.Target}
	for _, policy := range []CompositionPolicy{UnionCompositionPolicy, IntersectionCompositionPolicy} {
		assert.False(t, acl.AllowedWithPolicy(res, action.AuthorizeSession, globals.AnonymousUserId, policy).Authorized,
			"anonymous session authorization must be denied under %s", policy)
	}
}

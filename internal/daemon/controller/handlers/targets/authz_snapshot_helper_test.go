// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package targets

import (
	"testing"

	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/stretchr/testify/assert"
)

func TestBuildScopePath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		info *scopes.ScopeInfo
		want []string
	}{
		{name: "nil", info: nil, want: nil},
		{
			name: "global",
			info: &scopes.ScopeInfo{Id: "global", Type: "global"},
			want: []string{"global"},
		},
		{
			name: "org",
			info: &scopes.ScopeInfo{Id: "o_a", Type: "org", ParentScopeId: "global"},
			want: []string{"global", "o_a"},
		},
		{
			name: "project",
			info: &scopes.ScopeInfo{Id: "p_a", Type: "project", ParentScopeId: "o_a"},
			want: []string{"global", "o_a", "p_a"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, buildScopePath(tc.info))
		})
	}
}

func TestCompositionPolicyWire_DefaultsToUnion(t *testing.T) {
	t.Parallel()
	// The process-wide default is union; ensure the snapshot wire value tracks
	// it and switches when an intersection policy is selected.
	assert.Equal(t, "union", compositionPolicyWire())

	auth.SetGlobalCompositionPolicy(perms.IntersectionCompositionPolicy)
	assert.Equal(t, "intersection", compositionPolicyWire())

	// Restore the default so other tests are unaffected.
	auth.SetGlobalCompositionPolicy(perms.UnionCompositionPolicy)
	assert.Equal(t, "union", compositionPolicyWire())
}

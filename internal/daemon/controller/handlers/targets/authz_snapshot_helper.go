// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package targets

import (
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
)

// buildScopePath returns the ordered global->org->project scope id path for
// the resource the session targets. Missing intermediate ids are skipped, so
// a global/org resource yields a shorter path rather than an empty slot.
func buildScopePath(info *scopes.ScopeInfo) []string {
	if info == nil {
		return nil
	}
	path := make([]string, 0, 3)
	// ScopeInfo carries the current id and its parent id. The hierarchy is at
	// most global->org->project, so a fixed walk reconstructs the ordering
	// without a recursive lookup.
	switch info.Type {
	case "project":
		// The parent is an org; global is always the org's parent but ScopeInfo
		// does not carry the grandparent, so record global, org then project.
		path = append(path, "global")
		if info.ParentScopeId != "" {
			path = append(path, info.ParentScopeId)
		}
		path = append(path, info.Id)
	case "org":
		path = append(path, "global", info.Id)
	default:
		path = append(path, info.Id)
	}
	return path
}

// compositionPolicyWire resolves the active composition policy's
// configuration-wire string for snapshot persistence. It reads the same
// global resolution the ACL engine uses, defaulting to union.
func compositionPolicyWire() string {
	if auth.ActiveCompositionPolicy() == perms.IntersectionCompositionPolicy {
		return perms.IntersectionCompositionPolicy.String()
	}
	return perms.UnionCompositionPolicy.String()
}

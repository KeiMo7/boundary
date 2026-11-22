// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package perms

import (
	"context"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"golang.org/x/exp/slices"
)

// CompositionPolicy declares how grants coming from multiple scope layers
// are combined when deciding whether an action on a resource is authorized.
//
// The policy is always selected explicitly by configuration; it is never
// inferred from the shape of the grants. See
// docs/authz-hardening/design.md for the authoritative semantics.
type CompositionPolicy uint32

const (
	// UnknownCompositionPolicy is the zero value. It must never be used to
	// evaluate a request; callers are expected to resolve a concrete policy
	// (falling back to UnionCompositionPolicy) before reaching the engine.
	UnknownCompositionPolicy CompositionPolicy = iota

	// UnionCompositionPolicy authorizes when any applicable grant, across
	// every scope layer that contributes grants, matches the resource and
	// action. This is the historical Boundary behavior and the default.
	UnionCompositionPolicy

	// IntersectionCompositionPolicy authorizes only when, for every role
	// scope layer that contributes at least one applicable grant, at least
	// one of that layer's grants matches the resource and action. A layer
	// that participates but does not match causes a denial.
	IntersectionCompositionPolicy
)

// String returns the stable configuration-wire representation of the policy.
func (p CompositionPolicy) String() string {
	switch p {
	case UnionCompositionPolicy:
		return "union"
	case IntersectionCompositionPolicy:
		return "intersection"
	default:
		return "unknown"
	}
}

// CompositionPolicyFromString parses the configuration-wire representation.
// An empty string resolves to the union policy so that an absent
// configuration preserves the historical behavior. Any other unrecognized
// value returns an error rather than silently falling back, keeping the
// selection fail-closed.
func CompositionPolicyFromString(s string) (CompositionPolicy, error) {
	switch s {
	case "", "union":
		return UnionCompositionPolicy, nil
	case "intersection":
		return IntersectionCompositionPolicy, nil
	default:
		return UnknownCompositionPolicy, errors.New(
			context.Background(), errors.InvalidParameter, "perms.(CompositionPolicyFromString)",
			"scope composition policy must be \"union\" or \"intersection\"",
			errors.WithoutEvent(),
		)
	}
}

// applicableGrants returns the grants that could possibly apply to the
// resource, using the same collection rules the engine has always used:
// direct grants on the resource scope, children grants keyed by the
// resource's parent scope, and descendants grants (never for global).
func (a ACL) applicableGrants(r Resource) []AclGrant {
	grants := a.directScopeMap[r.ScopeId]
	grants = append(grants, a.childrenScopeMap[r.ParentScopeId]...)
	if r.ScopeId != scope.Global.String() {
		grants = append(grants, a.descendantsGrants...)
	}
	return grants
}

// grantMatches reports whether a single applicable grant authorizes the
// action on the resource. It encapsulates the action-matching and the five
// resource-matching cases of ACL.Allowed without mutating any result state.
// Output-fields-only grants never authorize an action.
func grantMatches(grant AclGrant, r Resource, aType, parentAction action.Type, userId string, skipAnonRestrictions bool) bool {
	var outputFieldsOnly bool
	switch {
	case len(grant.ActionSet) == 0:
		if _, hasSetFields := grant.OutputFields.Fields(); hasSetFields {
			outputFieldsOnly = true
		} else {
			return false
		}
	case grant.ActionSet[aType]:
		// We have this action.
	case grant.ActionSet[parentAction]:
		// Subaction satisfied by its parent action (e.g. read:self vs. read).
	case grant.ActionSet[action.All]:
		// All actions are allowed.
	default:
		return false
	}

	var found bool
	switch {
	// Case 1: anonymous user restrictions. Explicit type+action allow-lists
	// for scope discovery and auth method discovery/authentication.
	case !skipAnonRestrictions &&
		(userId == globals.AnonymousUserId || userId == ""):
		switch {
		case grant.Type == r.Type &&
			grant.Type == resource.Scope &&
			(aType == action.List || aType == action.NoOp):
			found = true
		case grant.Type == r.Type &&
			grant.Type == resource.AuthMethod &&
			(aType == action.List || aType == action.NoOp || aType == action.Authenticate):
			found = true
		}

	// Case 2: id=<resource.Id>;actions=<action>
	case grant.Id == r.Id &&
		grant.Id != "" &&
		grant.Id != "*" &&
		(grant.Type == resource.Unknown || grant.Type == globals.ResourceInfoFromPrefix(grant.Id).Type) &&
		!action.List.IsActionOrParent(aType) &&
		!action.Create.IsActionOrParent(aType):
		found = true

	// Case 3: typed collection create/list
	case grant.Id == "" &&
		r.Id == "" &&
		grant.Type == r.Type &&
		grant.Type != resource.Unknown &&
		r.Type.TopLevelType() &&
		(action.List.IsActionOrParent(aType) ||
			action.Create.IsActionOrParent(aType)):
		found = true

	// Case 4: id=*;type=<resource.Type>
	case grant.Id == "*" &&
		grant.Type != resource.Unknown &&
		(grant.Type == r.Type || grant.Type == resource.All):
		found = true

	// Case 5: id=<pin>;type=<resource.Type>
	case grant.Id != "" &&
		grant.Id == r.Pin &&
		grant.Type != resource.Unknown &&
		(grant.Type == r.Type || grant.Type == resource.All) &&
		!r.Type.TopLevelType():
		found = true
	}

	return found && !outputFieldsOnly
}

// AllowedWithPolicy evaluates the request under an explicitly selected
// composition policy. It is the single entry point that honors the
// configured semantics; Allowed remains a thin wrapper that preserves the
// historical union behavior.
//
// Under the intersection policy, grants are grouped by RoleScopeId (the
// scope of the role that sourced the grant). Every layer that contributes
// applicable grants must contain at least one matching grant. Layers with
// no applicable grants do not participate and therefore cannot deny; this
// keeps the policy meaningful without letting an unrelated global role veto
// a project-level authorization.
func (a ACL) AllowedWithPolicy(r Resource, aType action.Type, userId string, policy CompositionPolicy, opt ...Option) ACLResults {
	opts := getOpts(opt...)

	results := ACLResults{
		directScopeMap:    a.directScopeMap,
		childrenScopeMap:  a.childrenScopeMap,
		descendantsGrants: a.descendantsGrants,
	}

	var parentAction action.Type
	split := strings.Split(aType.String(), ":")
	if len(split) == 2 {
		parentAction = action.Map[split[0]]
	}

	grants := a.applicableGrants(r)

	// Output field accumulation must stay identical across policies, so a
	// first pass collects fields from every matching grant regardless of the
	// composition decision.
	matched := make([]bool, len(grants))
	for i, grant := range grants {
		matched[i] = grantMatches(grant, r, aType, parentAction, userId, opts.withSkipAnonymousUserRestrictions)
		if matched[i] {
			fields, _ := grant.OutputFields.Fields()
			results.OutputFields = results.OutputFields.AddFields(fields)
		}
	}

	switch policy {
	case IntersectionCompositionPolicy:
		// Group participating layer names in deterministic order so that the
		// decision is stable and testable.
		layerOrder := make([]string, 0)
		seenLayer := make(map[string]struct{})
		for _, g := range grants {
			if _, ok := seenLayer[g.RoleScopeId]; !ok {
				seenLayer[g.RoleScopeId] = struct{}{}
				layerOrder = append(layerOrder, g.RoleScopeId)
			}
		}
		slices.Sort(layerOrder)

		layerMatched := make(map[string]bool, len(layerOrder))
		for i, g := range grants {
			if matched[i] {
				layerMatched[g.RoleScopeId] = true
			}
		}
		results.Authorized = len(layerOrder) > 0
		for _, layer := range layerOrder {
			if !layerMatched[layer] {
				results.Authorized = false
				break
			}
		}

	default:
		// Union (and any defensively-defaulted value): first match wins,
		// matching the historical behavior.
		for _, ok := range matched {
			if ok {
				results.Authorized = true
				break
			}
		}
	}

	results.AuthenticationFinished = true
	return results
}

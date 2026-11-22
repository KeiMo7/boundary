// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package template

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// boundaryPrincipalPrefix marks identities minted for a Boundary session so
// target-side audit logs can distinguish them from locally provisioned
// accounts.
const boundaryPrincipalPrefix = "bnd"

// principalSuffixLength is the number of hex characters retained from the
// session id hash; 12 hex chars (48 bits) keep the identifier short while
// making collisions within one user practically impossible.
const principalSuffixLength = 12

// BoundaryPrincipal derives a stable, target-safe account identifier that
// binds a credential to a specific user and session. It is deterministic for
// the (userId, sessionId) pair so retries within one session render the same
// principal, and it never contains characters outside [a-z0-9_].
//
// Returns "" when either id is empty; callers then fall back to the library's
// default username rather than emitting a malformed identity.
func BoundaryPrincipal(userId, sessionId string) string {
	if userId == "" || sessionId == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(sessionId))
	suffix := hex.EncodeToString(sum[:])[:principalSuffixLength]
	return strings.Join([]string{boundaryPrincipalPrefix, sanitize(userId), suffix}, "_")
}

// sanitize reduces a Boundary public id to the charset target systems accept
// in usernames. Boundary ids are already [a-z0-9], but this guards against
// future id changes and strips any underscore-hostile character defensively.
func sanitize(in string) string {
	var b strings.Builder
	b.Grow(len(in))
	for _, r := range in {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

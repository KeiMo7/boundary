// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package template

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBoundaryPrincipal(t *testing.T) {
	t.Parallel()

	t.Run("deterministic and well formed", func(t *testing.T) {
		got := BoundaryPrincipal("u_alice1", "s_abc123")
		require.NotEmpty(t, got)
		assert.Regexp(t, regexp.MustCompile(`^bnd_u_alice1_[0-9a-f]{12}$`), got)
		// Same inputs render the same principal.
		assert.Equal(t, got, BoundaryPrincipal("u_alice1", "s_abc123"))
	})

	t.Run("different sessions differ", func(t *testing.T) {
		assert.NotEqual(t,
			BoundaryPrincipal("u_alice1", "s_001"),
			BoundaryPrincipal("u_alice1", "s_002"),
		)
	})

	t.Run("different users differ even for same session hash length", func(t *testing.T) {
		assert.NotEqual(t,
			BoundaryPrincipal("u_alice1", "s_x"),
			BoundaryPrincipal("u_bob001", "s_x"),
		)
	})

	t.Run("empty inputs yield empty rather than malformed identity", func(t *testing.T) {
		assert.Empty(t, BoundaryPrincipal("", "s_1"))
		assert.Empty(t, BoundaryPrincipal("u_1", ""))
	})

	t.Run("charset is target-username safe", func(t *testing.T) {
		got := BoundaryPrincipal("UPPER.CASE-1", "s_1")
		assert.Regexp(t, regexp.MustCompile(`^[a-z0-9_]+$`), got)
	})
}

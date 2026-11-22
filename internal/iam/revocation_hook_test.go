// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// recordingHook captures emitted events without touching a database.
type recordingHook struct {
	events []RevocationEvent
	err    error
}

func (h *recordingHook) OnAuthorizationRevoked(_ context.Context, ev RevocationEvent) error {
	h.events = append(h.events, ev)
	return h.err
}

func TestWithRevocationHook_DefaultsToNoop(t *testing.T) {
	t.Parallel()
	opts := getOpts()
	assert.NotNil(t, opts.withRevocationHook)
	assert.NoError(t, opts.withRevocationHook.OnAuthorizationRevoked(context.Background(), RevocationEvent{}))
}

func TestWithRevocationHook_NilResetsToNoop(t *testing.T) {
	t.Parallel()
	opts := getOpts(WithRevocationHook(nil))
	assert.IsType(t, noopRevocationHook{}, opts.withRevocationHook)
}

func TestEmitRevocation_RoutesEvent(t *testing.T) {
	t.Parallel()
	hook := &recordingHook{}
	repo := &Repository{revocationHook: hook}

	repo.emitRevocation(context.Background(), RevocationEvent{
		RoleId:       "r_1",
		Grants:       []string{"ids=*;type=target;actions=read"},
		ChangeReason: "grants-deleted",
	})
	requireLen(t, hook.events, 1)
	assert.Equal(t, "grants-deleted", hook.events[0].ChangeReason)
	assert.Equal(t, "r_1", hook.events[0].RoleId)
}

func TestEmitRevocation_SwallowsHookError(t *testing.T) {
	t.Parallel()
	// A hook failure must not panic or propagate; the reconciliation job is
	// the fallback.
	hook := &recordingHook{err: assertError("hook backend down")}
	repo := &Repository{revocationHook: hook}
	assert.NotPanics(t, func() {
		repo.emitRevocation(context.Background(), RevocationEvent{RoleId: "r_1", ChangeReason: "role-deleted"})
	})
	requireLen(t, hook.events, 1)
}

func TestEmitRevocation_IgnoresEmptyEventAndNilHook(t *testing.T) {
	t.Parallel()
	hook := &recordingHook{}
	repo := &Repository{revocationHook: hook}
	repo.emitRevocation(context.Background(), RevocationEvent{})
	assert.Empty(t, hook.events)

	// Nil hook (e.g. zero-value Repository in a low-level test) is safe.
	nilRepo := &Repository{}
	assert.NotPanics(t, func() {
		nilRepo.emitRevocation(context.Background(), RevocationEvent{RoleId: "r_1"})
	})
}

// requireLen avoids importing require in addition to assert in this small file.
func requireLen(t *testing.T, got any, want int) {
	t.Helper()
	if s, ok := got.([]RevocationEvent); ok {
		assert.Len(t, s, want)
	}
}

type assertError string

func (e assertError) Error() string { return string(e) }

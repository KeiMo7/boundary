// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
)

const defaultAuthzSnapshotTableName = "session_authz_snapshot"

// authzSnapshotRecord is the gorm-mapped representation of the
// session_authz_snapshot row. The domain AuthzSnapshot stays free of storage
// concerns; conversion to/from JSONB happens in this file.
type authzSnapshotRecord struct {
	SessionId         string `gorm:"primary_key"`
	UserId            string `gorm:"default:null"`
	AuthTokenId       string `gorm:"default:null"`
	ScopePath         []byte `gorm:"column:scope_path;type:jsonb;not null"`
	CompositionPolicy string `gorm:"column:composition_policy;not null"`
	GrantsHash        []byte `gorm:"default:null"`
	AuthzEntries      []byte `gorm:"column:authz_entries;type:jsonb;not null"`
	GrantsComplete    bool   `gorm:"column:grants_complete;not null;default:true"`
	CreateTime        *timestamp.Timestamp
	UpdateTime        *timestamp.Timestamp
	LastVerifiedAt    *timestamp.Timestamp `gorm:"default:null"`

	tableName string `gorm:"-"`
}

// TableName implements gorm.Tabler.
func (r *authzSnapshotRecord) TableName() string {
	if r.tableName != "" {
		return r.tableName
	}
	return defaultAuthzSnapshotTableName
}

// SetTableName allows the table name to be overridden in tests.
func (r *authzSnapshotRecord) SetTableName(n string) {
	r.tableName = n
}

// GetPublicId lets gorm LookupById resolve the primary key.
func (r *authzSnapshotRecord) GetPublicId() string {
	return r.SessionId
}

func toRecord(ctx context.Context, snap *AuthzSnapshot) (*authzSnapshotRecord, error) {
	const op = "session.toAuthzSnapshotRecord"
	switch {
	case snap == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing snapshot")
	case snap.SessionId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing session id")
	case len(snap.Entries) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "snapshot has no authorization entries")
	}
	scopePath, err := json.Marshal(snap.ScopePath)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to marshal scope path"))
	}
	entries, err := json.Marshal(snap.Entries)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to marshal authz entries"))
	}
	return &authzSnapshotRecord{
		SessionId:         snap.SessionId,
		UserId:            snap.UserId,
		AuthTokenId:       snap.AuthTokenId,
		ScopePath:         scopePath,
		CompositionPolicy: snap.CompositionPolicy,
		GrantsHash:        snap.GrantsHash,
		AuthzEntries:      entries,
		GrantsComplete:    snap.GrantsComplete,
	}, nil
}

func (r *authzSnapshotRecord) toDomain(ctx context.Context) (*AuthzSnapshot, error) {
	const op = "session.(authzSnapshotRecord).toDomain"
	var scopePath []string
	if err := json.Unmarshal(r.ScopePath, &scopePath); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to unmarshal scope path"))
	}
	var entries []AuthzSnapshotEntry
	if err := json.Unmarshal(r.AuthzEntries, &entries); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to unmarshal authz entries"))
	}
	return &AuthzSnapshot{
		SessionId:         r.SessionId,
		UserId:            r.UserId,
		AuthTokenId:       r.AuthTokenId,
		ScopePath:         scopePath,
		CompositionPolicy: r.CompositionPolicy,
		GrantsHash:        r.GrantsHash,
		Entries:           entries,
		GrantsComplete:    r.GrantsComplete,
	}, nil
}

// CreateAuthzSnapshot persists the snapshot. It is intended to be called
// inside the CreateSession transaction so the session row and its
// authorization snapshot commit atomically.
func (r *Repository) CreateAuthzSnapshot(ctx context.Context, snap *AuthzSnapshot) error {
	const op = "session.(Repository).CreateAuthzSnapshot"
	record, err := toRecord(ctx, snap)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if err := r.writer.Create(ctx, record); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// LookupAuthzSnapshot returns the snapshot for a session, or nil without an
// error when none exists.
func (r *Repository) LookupAuthzSnapshot(ctx context.Context, sessionId string) (*AuthzSnapshot, error) {
	const op = "session.(Repository).LookupAuthzSnapshot"
	if sessionId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing session id")
	}
	record := &authzSnapshotRecord{SessionId: sessionId}
	if err := r.reader.LookupById(ctx, record); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op)
	}
	return record.toDomain(ctx)
}

// ListOpenAuthzSnapshots returns snapshots for sessions still in pending or
// active state. The reconciliation job uses it to re-evaluate live
// authorization; the per-user scoping happens before any invalidation so
// unrelated users are never touched.
func (r *Repository) ListOpenAuthzSnapshots(ctx context.Context) ([]*AuthzSnapshot, error) {
	const op = "session.(Repository).ListOpenAuthzSnapshots"
	var records []*authzSnapshotRecord
	err := r.reader.SearchWhere(
		ctx,
		&records,
		`exists (
			select 1 from session_state sst
			where sst.session_id = session_authz_snapshot.session_id
			  and sst.state in ('pending', 'active')
		)`,
		nil,
		db.WithLimit(-1),
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	out := make([]*AuthzSnapshot, 0, len(records))
	for _, rec := range records {
		snap, convErr := rec.toDomain(ctx)
		if convErr != nil {
			return nil, errors.Wrap(ctx, convErr, op)
		}
		out = append(out, snap)
	}
	return out, nil
}

// MarkAuthzSnapshotVerified stamps last_verified_at after a successful
// reconciliation pass.
func (r *Repository) MarkAuthzSnapshotVerified(ctx context.Context, sessionId string) error {
	const op = "session.(Repository).MarkAuthzSnapshotVerified"
	if sessionId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing session id")
	}
	if _, err := r.writer.Exec(ctx,
		`update session_authz_snapshot set last_verified_at = now() where session_id = ?`,
		[]any{sessionId},
	); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// CancelSessionForRevocation drives a session into the canceling state because
// its authorization was revoked. It resolves the current version itself so it
// can be invoked from the revocation hook or reconciliation job without a
// prior LookupSession. It is idempotent: an already-canceling session is left
// in place. The termination reason is recorded as authorization revoked.
func (r *Repository) CancelSessionForRevocation(ctx context.Context, sessionId string) error {
	const op = "session.(Repository).CancelSessionForRevocation"
	if sessionId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing session id")
	}
	sess, _, err := r.LookupSession(ctx, sessionId)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if sess == nil {
		return errors.New(ctx, errors.RecordNotFound, op, "session not found")
	}
	// Idempotent: nothing to do once the session is already leaving the
	// active/pending set.
	if sess.TerminationReason != "" {
		return nil
	}
	if _, _, err := r.updateState(ctx, sessionId, sess.Version, StatusCanceling); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if _, err := r.writer.Exec(ctx,
		`update session set termination_reason = ? where public_id = ? and termination_reason is null`,
		[]any{string(AuthorizationRevoked), sessionId},
	); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

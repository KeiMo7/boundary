-- Copyright IBM Corp. 2020, 2026
-- SPDX-License-Identifier: BUSL-1.1

-- session_authz_snapshot stores the point-in-time authorization state captured
-- when a session is established. It is written in the same transaction as the
-- session row so a session can never exist without a snapshot, and it is removed
-- automatically when the session is deleted. The snapshot drives revocation
-- reconciliation: live grants are compared item-by-item against authz_entries
-- and a mismatch invalidates the session. See
-- docs/authz-hardening/design.md.

begin;

create table session_authz_snapshot (
  -- one snapshot per session
  session_id wt_public_id primary key
    references session (public_id)
    on delete cascade
    on update cascade,
  user_id wt_public_id
    references iam_user (public_id)
    on delete set null
    on update cascade,
  auth_token_id wt_public_id
    references auth_token (public_id)
    on delete set null
    on update cascade,
  -- ordered global->org->project scope id path of the target resource
  scope_path jsonb not null
    constraint session_authz_snapshot_scope_path_is_array
      check (jsonb_typeof(scope_path) = 'array'),
  -- the perms composition policy in effect at authorization time
  composition_policy text not null
    constraint session_authz_snapshot_composition_policy_chk
      check (composition_policy in ('union', 'intersection')),
  -- stable fnv hash of the full grant tuple set, for fast change detection
  grants_hash bytea,
  -- itemized role/grant/principal/membership entries; the comparison unit for
  -- revocation. Never null; an empty array is rejected because a session cannot
  -- be authorized without at least one contributing grant.
  authz_entries jsonb not null
    constraint session_authz_snapshot_entries_is_array
      check (jsonb_typeof(authz_entries) = 'array'),
  -- false when the grant load could not be trusted; forces conservative
  -- invalidation during reconciliation
  grants_complete boolean not null default true,
  create_time wt_timestamp,
  update_time wt_timestamp,
  -- last time the reconciliation job successfully re-verified this snapshot
  last_verified_at wt_timestamp
);

comment on table session_authz_snapshot is
  'session_authz_snapshot records the exact role, grant and scope-path authorization captured when each session was established, enabling permission revocation to propagate to live sessions';

-- snapshots are immutable except for the bookkeeping verification timestamp.
create trigger immutable_columns before update on session_authz_snapshot
  for each row execute procedure immutable_columns(
    'session_id', 'user_id', 'auth_token_id', 'scope_path',
    'composition_policy', 'grants_hash', 'authz_entries',
    'grants_complete', 'create_time'
  );

create trigger default_create_time_column before insert on session_authz_snapshot
  for each row execute procedure default_create_time();

create trigger update_time_column before update on session_authz_snapshot
  for each row execute procedure update_time_column();

-- Reconciliation scans look up open sessions by user and verification time.
create index session_authz_snapshot_user_id_idx
  on session_authz_snapshot (user_id);

commit;

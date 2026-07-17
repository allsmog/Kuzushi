pub(super) const PROJECTION_SCHEMA: &str = r#"
create table if not exists meta (
  key text primary key,
  value text not null
);

insert or ignore into meta(key, value) values
  ('schema_version', '3'),
  ('applied_seq', '0'),
  ('generation', '0'),
  ('fts_available', '0');

create table if not exists target_snapshots (
  snapshot_hash text primary key,
  tree_hash text not null,
  workspace_root_fingerprint text not null,
  git_commit text,
  git_branch text,
  dirty_hash text,
  index_hash text,
  config_hash text,
  created_at text not null
);

create table if not exists blobs (
  blob_hash text primary key,
  size_bytes integer not null,
  media_type text,
  storage_path text not null
);

create table if not exists run_events (
  event_hash text primary key,
  seq integer not null unique,
  run_id text not null,
  event_kind text not null,
  target text,
  status text not null,
  findings_count integer,
  actor text not null,
  created_at text not null,
  payload_json text not null
);
create index if not exists idx_run_events_run_seq
  on run_events(run_id, seq asc);

create table if not exists run_states (
  run_id text primary key,
  target text,
  status text not null,
  findings_count integer,
  started_seq integer,
  completed_seq integer,
  updated_seq integer not null,
  updated_at text not null
);

create table if not exists indexed_files (
  snapshot_hash text not null,
  path text not null,
  blob_hash text not null,
  file_size integer not null,
  mtime_ns integer,
  git_blob_oid text,
  language text,
  ast_hash text,
  indexed_at text not null,
  primary key (snapshot_hash, path)
);

create table if not exists file_deletions (
  event_hash text primary key,
  seq integer not null unique,
  snapshot_hash text not null,
  path text not null,
  actor text not null,
  created_at text not null
);
create index if not exists idx_file_deletions_snapshot_path
  on file_deletions(snapshot_hash, path, seq desc);

create table if not exists attack_surface_snapshots (
  event_hash text primary key,
  seq integer not null unique,
  snapshot_hash text not null,
  run_id text,
  object_hash text,
  summary text not null,
  actor text not null,
  created_at text not null,
  payload_json text not null
);
create index if not exists idx_attack_surface_snapshots_snapshot
  on attack_surface_snapshots(snapshot_hash, seq desc);

create table if not exists finding_observations (
  observation_hash text primary key,
  stable_fp text not null,
  snapshot_hash text not null,
  run_id text not null,
  tool text not null,
  tool_version text,
  rule_id text not null,
  rule_set_hash text,
  severity text not null,
  title text not null,
  message text not null,
  blob_hash text,
  byte_start integer,
  byte_end integer,
  display_path text,
  display_line integer,
  raw_result_hash text not null,
  finding_json text,
  created_seq integer not null,
  created_at text not null
);
create index if not exists idx_finding_observations_stable_fp
  on finding_observations(stable_fp, created_seq desc);

create table if not exists finding_identities (
  identity_id text primary key,
  target_id text not null,
  alias text not null,
  fingerprint_current text not null,
  first_seen_run_id text not null,
  created_at text not null,
  retired_at text,
  unique(target_id, alias)
);
create index if not exists idx_finding_identities_target
  on finding_identities(target_id, created_at asc);
create index if not exists idx_finding_identities_fingerprint_current
  on finding_identities(fingerprint_current);

create table if not exists finding_identity_fingerprints (
  identity_id text not null references finding_identities(identity_id) on delete cascade,
  fingerprint text not null,
  match_basis text not null,
  created_at text not null,
  primary key(identity_id, fingerprint)
);
create index if not exists idx_finding_identity_fingerprints_fingerprint
  on finding_identity_fingerprints(fingerprint);

create table if not exists finding_current (
  id integer primary key,
  run_id text not null,
  identity_id text not null,
  identity_match_tier text not null,
  fingerprint text not null,
  created_at text not null,
  updated_at text not null,
  dedup_key text,
  source_signature text,
  finding_json text not null,
  unique(run_id, fingerprint)
);
create index if not exists idx_finding_current_dedup_key
  on finding_current(dedup_key) where dedup_key is not null;
create index if not exists idx_finding_current_run_dedup_key
  on finding_current(run_id, dedup_key) where dedup_key is not null;
create index if not exists idx_finding_current_identity_id
  on finding_current(identity_id);

create table if not exists stable_findings (
  stable_fp text primary key,
  current_status text not null,
  canonical_severity text not null,
  canonical_title text not null,
  canonical_path text,
  first_seen_seq integer not null,
  last_seen_seq integer not null,
  last_observation_hash text,
  updated_seq integer not null
);

create table if not exists finding_events (
  event_hash text primary key,
  seq integer not null unique,
  stable_fp text,
  event_kind text not null,
  payload_json text not null,
  actor text not null,
  created_at text not null
);
create index if not exists idx_finding_events_stable_fp_seq
  on finding_events(stable_fp, seq desc)
  where stable_fp is not null;

create table if not exists rekey_edges (
  old_fp text not null,
  new_fp text not null,
  event_hash text not null,
  method text not null,
  confidence real not null,
  primary key (old_fp, new_fp, event_hash)
);

create table if not exists review_decisions (
  id integer primary key autoincrement,
  finding_id integer not null,
  identity_id text,
  decision_verdict text not null,
  triage_verdict text,
  confidence real not null,
  rationale text not null,
  author text not null,
  created_at text not null,
  dismiss_reason text,
  dismissed_by text
);
create index if not exists idx_review_decisions_finding
  on review_decisions(finding_id, created_at desc, id desc);
create index if not exists idx_review_decisions_identity
  on review_decisions(identity_id, created_at desc, id desc)
  where identity_id is not null;

create table if not exists verification_events (
  event_hash text primary key,
  seq integer not null unique,
  stable_fp text not null,
  finding_id integer,
  identity_id text,
  verification_run_id text,
  verified_scan_id text,
  proof_level integer not null,
  proof_verdict text not null,
  backend text not null,
  language text,
  harness_path text,
  crash_evidence text,
  duration_ms integer not null,
  cost_usd real not null,
  notes_json text not null,
  actor text not null,
  created_at text not null,
  payload_json text not null
);
create index if not exists idx_verification_events_stable_fp
  on verification_events(stable_fp, seq desc);
create index if not exists idx_verification_events_finding
  on verification_events(finding_id, seq desc)
  where finding_id is not null;

create table if not exists patch_attempt_events (
  event_hash text primary key,
  seq integer not null unique,
  stable_fp text not null,
  fingerprint text not null,
  patch_run_id text not null,
  repo text not null,
  diff_object text,
  diff_size_bytes integer,
  status text not null,
  iterations integer not null,
  build_command text,
  test_command text,
  worktree_path text,
  cost_usd real,
  provider_spend_unresolved integer,
  validator_log text,
  history_json text not null,
  actor text not null,
  created_at text not null,
  payload_json text not null
);
create index if not exists idx_patch_attempt_events_stable_fp
  on patch_attempt_events(stable_fp, seq desc);
create index if not exists idx_patch_attempt_events_run
  on patch_attempt_events(patch_run_id);

create table if not exists patch_lifecycle_events (
  event_hash text primary key,
  seq integer not null unique,
  application_id text not null,
  stable_fp text not null,
  fingerprint text not null,
  finding_scan_id text,
  patch_run_id text not null,
  target text not null,
  diff_hash text not null,
  base_commit text,
  touched_files_json text not null,
  state text not null,
  reverify_run_id text,
  detail text,
  actor text not null,
  application_started_at text not null,
  applied_at text not null,
  updated_at text not null,
  created_at text not null,
  payload_json text not null
);
create index if not exists idx_patch_lifecycle_events_application
  on patch_lifecycle_events(application_id, seq desc);
create index if not exists idx_patch_lifecycle_events_stable_fp
  on patch_lifecycle_events(stable_fp, seq desc);

create table if not exists patch_lifecycle_current (
  application_id text primary key,
  latest_seq integer not null,
  stable_fp text not null,
  fingerprint text not null,
  finding_scan_id text,
  patch_run_id text not null,
  target text not null,
  diff_hash text not null,
  base_commit text,
  touched_files_json text not null,
  state text not null,
  reverify_run_id text,
  detail text,
  actor text not null,
  application_started_at text not null,
  applied_at text not null,
  updated_at text not null
);
create index if not exists idx_patch_lifecycle_current_stable_fp
  on patch_lifecycle_current(stable_fp, latest_seq desc);
create index if not exists idx_patch_lifecycle_current_fingerprint
  on patch_lifecycle_current(fingerprint, latest_seq desc);

create table if not exists audit_events (
  event_hash text primary key,
  seq integer not null unique,
  event_kind text not null,
  actor text not null,
  run_id text,
  stable_fp text,
  subject text,
  summary text not null,
  payload_json text not null,
  created_at text not null
);
create index if not exists idx_audit_events_kind_seq
  on audit_events(event_kind, seq desc);
create index if not exists idx_audit_events_run_seq
  on audit_events(run_id, seq desc)
  where run_id is not null;
create index if not exists idx_audit_events_stable_fp_seq
  on audit_events(stable_fp, seq desc)
  where stable_fp is not null;

create table if not exists finding_search_content (
  rowid integer primary key,
  stable_fp text not null unique,
  title text,
  message text,
  rule_id text,
  display_path text,
  evidence text,
  triage_text text,
  verification_text text
);
"#;

pub(super) const FTS_SCHEMA: &str = r#"
create virtual table if not exists finding_search using fts5(
  stable_fp unindexed,
  title,
  message,
  rule_id,
  display_path,
  evidence,
  triage_text,
  verification_text,
  content='finding_search_content',
  content_rowid='rowid',
  tokenize='unicode61 remove_diacritics 2'
);
"#;

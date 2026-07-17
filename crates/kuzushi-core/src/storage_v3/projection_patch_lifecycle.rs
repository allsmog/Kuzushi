use crate::event_log::{EventEnvelope, EventKind};
use anyhow::{Context, Result};
use rusqlite::{params, Transaction};

use super::projection_payload::{payload_str, require_payload_str};
use super::sql_seq;

pub(super) fn project_patch_lifecycle_event(
    tx: &Transaction<'_>,
    event: &EventEnvelope,
) -> Result<()> {
    if event.event_kind != EventKind::PatchLifecycleRecorded {
        return Ok(());
    }
    let touched_files = event
        .payload
        .get("touchedFiles")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let touched_files_json = serde_json::to_string(&touched_files)
        .context("Could not serialize patch lifecycle touched files")?;
    let values = lifecycle_values(event, &touched_files_json)?;
    insert_event(tx, &values)?;
    upsert_current(tx, &values)?;
    Ok(())
}

struct LifecycleValues<'a> {
    event: &'a EventEnvelope,
    application_id: &'a str,
    stable_fp: &'a str,
    fingerprint: &'a str,
    finding_scan_id: Option<&'a str>,
    patch_run_id: &'a str,
    target: &'a str,
    diff_hash: &'a str,
    base_commit: Option<&'a str>,
    touched_files_json: &'a str,
    state: &'a str,
    reverify_run_id: Option<&'a str>,
    detail: Option<&'a str>,
    application_started_at: &'a str,
    applied_at: Option<&'a str>,
    updated_at: &'a str,
}

fn lifecycle_values<'a>(
    event: &'a EventEnvelope,
    touched_files_json: &'a str,
) -> Result<LifecycleValues<'a>> {
    Ok(LifecycleValues {
        event,
        application_id: require_payload_str(&event.payload, "applicationId")?,
        stable_fp: require_payload_str(&event.payload, "stableFp")?,
        fingerprint: require_payload_str(&event.payload, "fingerprint")?,
        finding_scan_id: payload_str(&event.payload, "findingScanId"),
        patch_run_id: require_payload_str(&event.payload, "patchRunId")?,
        target: require_payload_str(&event.payload, "target")?,
        diff_hash: require_payload_str(&event.payload, "diffHash")?,
        base_commit: payload_str(&event.payload, "baseCommit"),
        touched_files_json,
        state: require_payload_str(&event.payload, "state")?,
        reverify_run_id: payload_str(&event.payload, "reverifyRunId"),
        detail: payload_str(&event.payload, "detail"),
        application_started_at: payload_str(&event.payload, "applicationStartedAt")
            .or_else(|| payload_str(&event.payload, "appliedAt"))
            .unwrap_or(event.created_at.as_str()),
        applied_at: payload_str(&event.payload, "appliedAt"),
        updated_at: require_payload_str(&event.payload, "updatedAt")?,
    })
}

fn insert_event(tx: &Transaction<'_>, values: &LifecycleValues<'_>) -> Result<()> {
    tx.execute(
        r#"
        insert into patch_lifecycle_events(
          event_hash, seq, application_id, stable_fp, fingerprint,
          finding_scan_id, patch_run_id, target, diff_hash, base_commit,
          touched_files_json, state, reverify_run_id, detail, actor,
          application_started_at, applied_at, updated_at, created_at, payload_json
        ) values (
          ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
          ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20
        )
        on conflict(event_hash) do nothing
        "#,
        params![
            values.event.event_hash.as_str(),
            sql_seq(values.event.seq)?,
            values.application_id,
            values.stable_fp,
            values.fingerprint,
            values.finding_scan_id,
            values.patch_run_id,
            values.target,
            values.diff_hash,
            values.base_commit,
            values.touched_files_json,
            values.state,
            values.reverify_run_id,
            values.detail,
            values.event.actor,
            values.application_started_at,
            values.applied_at.unwrap_or(""),
            values.updated_at,
            values.event.created_at,
            values.event.payload.to_string(),
        ],
    )?;
    Ok(())
}

fn upsert_current(tx: &Transaction<'_>, values: &LifecycleValues<'_>) -> Result<()> {
    tx.execute(
        PATCH_LIFECYCLE_CURRENT_UPSERT,
        params![
            values.application_id,
            sql_seq(values.event.seq)?,
            values.stable_fp,
            values.fingerprint,
            values.finding_scan_id,
            values.patch_run_id,
            values.target,
            values.diff_hash,
            values.base_commit,
            values.touched_files_json,
            values.state,
            values.reverify_run_id,
            values.detail,
            values.event.actor,
            values.application_started_at,
            values.applied_at.unwrap_or(""),
            values.updated_at,
        ],
    )?;
    Ok(())
}

const PATCH_LIFECYCLE_CURRENT_UPSERT: &str = r#"
insert into patch_lifecycle_current(
  application_id, latest_seq, stable_fp, fingerprint, finding_scan_id,
  patch_run_id, target, diff_hash, base_commit, touched_files_json,
  state, reverify_run_id, detail, actor, application_started_at,
  applied_at, updated_at
) values (
  ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
  ?11, ?12, ?13, ?14, ?15, ?16, ?17
)
on conflict(application_id) do update set
  latest_seq = excluded.latest_seq,
  stable_fp = excluded.stable_fp,
  fingerprint = excluded.fingerprint,
  finding_scan_id = excluded.finding_scan_id,
  patch_run_id = excluded.patch_run_id,
  target = excluded.target,
  diff_hash = excluded.diff_hash,
  base_commit = excluded.base_commit,
  touched_files_json = excluded.touched_files_json,
  state = excluded.state,
  reverify_run_id = excluded.reverify_run_id,
  detail = excluded.detail,
  actor = excluded.actor,
  application_started_at = excluded.application_started_at,
  applied_at = excluded.applied_at,
  updated_at = excluded.updated_at
where excluded.latest_seq >= patch_lifecycle_current.latest_seq
"#;

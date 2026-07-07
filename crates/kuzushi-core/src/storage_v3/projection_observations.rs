use super::projection_fts::rebuild_fts_if_available;
use super::projection_payload::{payload_i64, payload_str, require_payload_str};
use crate::event_log::{EventEnvelope, EventKind};
use anyhow::{Context, Result};
use rusqlite::{params, Transaction};
use serde_json::Value;

use super::sql_seq;

const INSERT_FINDING_OBSERVATION_SQL: &str = r#"
insert into finding_observations(
  observation_hash, stable_fp, snapshot_hash, run_id, tool, tool_version,
  rule_id, rule_set_hash, severity, title, message, blob_hash, byte_start,
  byte_end, display_path, display_line, raw_result_hash, finding_json,
  created_seq, created_at
)
values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
on conflict(observation_hash) do nothing
"#;

pub(super) fn project_finding_observation(
    tx: &Transaction<'_>,
    event: &EventEnvelope,
) -> Result<Option<i64>> {
    if event.event_kind != EventKind::FindingObserved {
        return Ok(None);
    }
    let observation = FindingObservationProjection::from_event(event)?;
    let current = project_current_finding(tx, event)?;
    insert_finding_observation(tx, event, &observation, current.as_ref())?;
    project_stable_finding(tx, event, &observation)?;
    project_observation_search(tx, event, &observation)?;
    Ok(current.map(|current| current.id))
}

struct FindingObservationProjection<'a> {
    observation_hash: &'a str,
    stable_fp: &'a str,
    snapshot_hash: &'a str,
    run_id: &'a str,
    tool: &'a str,
    rule_id: &'a str,
    severity: &'a str,
    title: &'a str,
    message: &'a str,
    raw_result_hash: &'a str,
}

impl<'a> FindingObservationProjection<'a> {
    fn from_event(event: &'a EventEnvelope) -> Result<Self> {
        Ok(Self {
            observation_hash: require_payload_str(&event.payload, "observationHash")?,
            stable_fp: require_payload_str(&event.payload, "stableFp")?,
            snapshot_hash: require_payload_str(&event.payload, "snapshotHash")?,
            run_id: require_payload_str(&event.payload, "runId")?,
            tool: require_payload_str(&event.payload, "tool")?,
            rule_id: require_payload_str(&event.payload, "ruleId")?,
            severity: require_payload_str(&event.payload, "severity")?,
            title: require_payload_str(&event.payload, "title")?,
            message: require_payload_str(&event.payload, "message")?,
            raw_result_hash: require_payload_str(&event.payload, "rawResultHash")?,
        })
    }
}

fn insert_finding_observation(
    tx: &Transaction<'_>,
    event: &EventEnvelope,
    observation: &FindingObservationProjection<'_>,
    current: Option<&CurrentFindingProjection>,
) -> Result<()> {
    tx.execute(
        INSERT_FINDING_OBSERVATION_SQL,
        params![
            observation.observation_hash,
            observation.stable_fp,
            observation.snapshot_hash,
            observation.run_id,
            observation.tool,
            payload_str(&event.payload, "toolVersion"),
            observation.rule_id,
            payload_str(&event.payload, "ruleSetHash"),
            observation.severity,
            observation.title,
            observation.message,
            payload_str(&event.payload, "blobHash"),
            payload_i64(&event.payload, "byteStart"),
            payload_i64(&event.payload, "byteEnd"),
            payload_str(&event.payload, "displayPath"),
            payload_i64(&event.payload, "displayLine"),
            observation.raw_result_hash,
            current
                .map(|current| current.finding_json.as_str())
                .or_else(|| payload_str(&event.payload, "findingJson")),
            sql_seq(event.seq)?,
            event.created_at,
        ],
    )?;
    Ok(())
}

struct CurrentFindingProjection {
    id: i64,
    finding_json: String,
}

fn project_current_finding(
    tx: &Transaction<'_>,
    event: &EventEnvelope,
) -> Result<Option<CurrentFindingProjection>> {
    let Some(raw_finding) = payload_str(&event.payload, "findingJson") else {
        return Ok(None);
    };
    let projected_id = payload_i64(&event.payload, "projectedFindingId")
        .context("finding observation payload requires projectedFindingId")?;
    let mut finding = parse_finding_json(raw_finding)?;
    set_json_i64(&mut finding, "id", projected_id)?;
    let projection = CurrentFindingProjection {
        id: projected_id,
        finding_json: serde_json::to_string(&finding)
            .context("Could not serialize current finding projection")?,
    };
    upsert_current_finding(tx, event, &finding, &projection)?;
    Ok(Some(projection))
}

fn parse_finding_json(raw: &str) -> Result<Value> {
    serde_json::from_str(raw).context("Could not parse finding projection JSON")
}

fn set_json_i64(value: &mut Value, key: &str, next: i64) -> Result<()> {
    let object = value
        .as_object_mut()
        .context("finding projection JSON must be an object")?;
    object.insert(key.to_string(), Value::from(next));
    Ok(())
}

fn upsert_current_finding(
    tx: &Transaction<'_>,
    event: &EventEnvelope,
    finding: &Value,
    projection: &CurrentFindingProjection,
) -> Result<()> {
    tx.execute(
        r#"
        insert into finding_current(
          id, run_id, identity_id, identity_match_tier, fingerprint, created_at,
          updated_at, dedup_key, source_signature, finding_json
        )
        values (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7, ?8, ?9)
        on conflict(id) do update set
          run_id = excluded.run_id,
          identity_id = excluded.identity_id,
          identity_match_tier = excluded.identity_match_tier,
          updated_at = excluded.updated_at,
          dedup_key = coalesce(excluded.dedup_key, finding_current.dedup_key),
          source_signature = coalesce(excluded.source_signature, finding_current.source_signature),
          finding_json = excluded.finding_json
        "#,
        params![
            projection.id,
            require_payload_str(&event.payload, "runId")?,
            json_str(finding, "identityId")?,
            json_str(finding, "identityMatchTier")?,
            json_str(finding, "fingerprint")?,
            event.created_at,
            json_optional_str(finding, "dedup_key"),
            json_optional_str(finding, "source_signature"),
            projection.finding_json,
        ],
    )?;
    Ok(())
}

fn json_str<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("finding projection JSON requires {key}"))
}

fn json_optional_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn project_stable_finding(
    tx: &Transaction<'_>,
    event: &EventEnvelope,
    observation: &FindingObservationProjection<'_>,
) -> Result<()> {
    tx.execute(
        r#"
        insert into stable_findings(
          stable_fp, current_status, canonical_severity, canonical_title,
          canonical_path, first_seen_seq, last_seen_seq, last_observation_hash, updated_seq
        )
        values (?1, 'open', ?2, ?3, ?4, ?5, ?5, ?6, ?5)
        on conflict(stable_fp) do update set
          current_status = 'open',
          canonical_severity = excluded.canonical_severity,
          canonical_title = excluded.canonical_title,
          canonical_path = excluded.canonical_path,
          last_seen_seq = excluded.last_seen_seq,
          last_observation_hash = excluded.last_observation_hash,
          updated_seq = excluded.updated_seq
        "#,
        params![
            observation.stable_fp,
            observation.severity,
            observation.title,
            payload_str(&event.payload, "displayPath"),
            sql_seq(event.seq)?,
            observation.observation_hash,
        ],
    )?;
    Ok(())
}

fn project_observation_search(
    tx: &Transaction<'_>,
    event: &EventEnvelope,
    observation: &FindingObservationProjection<'_>,
) -> Result<()> {
    tx.execute(
        r#"
        insert into finding_search_content(stable_fp, title, message, rule_id, display_path)
        values (?1, ?2, ?3, ?4, ?5)
        on conflict(stable_fp) do update set
          title = excluded.title,
          message = excluded.message,
          rule_id = excluded.rule_id,
          display_path = excluded.display_path
        "#,
        params![
            observation.stable_fp,
            observation.title,
            observation.message,
            observation.rule_id,
            payload_str(&event.payload, "displayPath"),
        ],
    )?;
    rebuild_fts_if_available(tx)
}

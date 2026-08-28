use super::projection_fts::rebuild_fts_if_available;
use super::projection_payload::{payload_i64, payload_str, require_payload_str};
use crate::event_log::{EventEnvelope, EventKind};
use crate::findings::FindingIdentityBasis;
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
    project_identity_link(tx, event, current.as_ref())?;
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
    created_at: Option<String>,
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
        created_at: json_optional_non_empty_str(&finding, "created_at").map(str::to_string),
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
          id, run_id, identity_id, identity_match_tier, identity_basis,
          fingerprint, created_at, updated_at, dedup_key, source_signature,
          finding_json
        )
        values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8, ?9, ?10)
        on conflict(id) do update set
          run_id = excluded.run_id,
          identity_id = excluded.identity_id,
          identity_match_tier = excluded.identity_match_tier,
          identity_basis = coalesce(excluded.identity_basis, finding_current.identity_basis),
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
            json_optional_str(finding, "identityBasis"),
            json_str(finding, "fingerprint")?,
            event.created_at,
            json_optional_str(finding, "dedup_key"),
            json_optional_str(finding, "source_signature"),
            projection.finding_json,
        ],
    )?;
    Ok(())
}

fn project_identity_link(
    tx: &Transaction<'_>,
    event: &EventEnvelope,
    current: Option<&CurrentFindingProjection>,
) -> Result<()> {
    let Some(identity_id) = payload_str(&event.payload, "identityId") else {
        return Ok(());
    };
    let run_id = require_payload_str(&event.payload, "runId")?;
    let run = identity_run_context(tx, run_id)?;
    let created_at = current
        .and_then(|projection| projection.created_at.as_deref())
        .unwrap_or(run.started_at.as_str());
    let match_tier = payload_str(&event.payload, "identityMatchTier")
        .or_else(|| payload_str(&event.payload, "identityMatchBasis"))
        .context("finding identity projection requires an identity match tier")?;
    let basis = payload_str(&event.payload, "identityMatchBasis")
        .filter(|value| FindingIdentityBasis::from_str(value).is_some());
    insert_identity(
        tx,
        &IdentityProjection {
            identity_id,
            target_id: &run.target_id,
            alias: require_payload_str(&event.payload, "identityAlias")?,
            fingerprint: require_payload_str(&event.payload, "identityFingerprint")?,
            match_tier,
            basis,
            run_id,
            created_at,
        },
    )
}

struct IdentityRunContext {
    target_id: String,
    started_at: String,
}

fn identity_run_context(tx: &Transaction<'_>, run_id: &str) -> Result<IdentityRunContext> {
    tx.query_row(
        "select target, updated_at from run_states where run_id = ?1",
        params![run_id],
        |row| {
            Ok(IdentityRunContext {
                target_id: row.get(0)?,
                started_at: row.get(1)?,
            })
        },
    )
    .with_context(|| format!("finding identity projection requires run {run_id:?}"))
}

struct IdentityProjection<'a> {
    identity_id: &'a str,
    target_id: &'a str,
    alias: &'a str,
    fingerprint: &'a str,
    match_tier: &'a str,
    basis: Option<&'a str>,
    run_id: &'a str,
    created_at: &'a str,
}

fn insert_identity(tx: &Transaction<'_>, identity: &IdentityProjection<'_>) -> Result<()> {
    tx.execute(
        r#"
        insert into finding_identities(
          identity_id, target_id, alias, fingerprint_current,
          first_seen_run_id, created_at
        )
        values (?1, ?2, ?3, ?4, ?5, ?6)
        on conflict(identity_id) do nothing
        "#,
        params![
            identity.identity_id,
            identity.target_id,
            identity.alias,
            identity.fingerprint,
            identity.run_id,
            identity.created_at,
        ],
    )?;
    insert_identity_fingerprint(tx, identity)
}

fn insert_identity_fingerprint(
    tx: &Transaction<'_>,
    identity: &IdentityProjection<'_>,
) -> Result<()> {
    tx.execute(
        r#"
        insert into finding_identity_fingerprints(
          identity_id, fingerprint, match_basis, identity_basis, created_at
        )
        values (?1, ?2, ?3, ?4, ?5)
        on conflict(identity_id, fingerprint) do update set
          identity_basis = coalesce(
            excluded.identity_basis,
            finding_identity_fingerprints.identity_basis
          )
        "#,
        params![
            identity.identity_id,
            identity.fingerprint,
            identity.match_tier,
            identity.basis,
            identity.created_at,
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

fn json_optional_non_empty_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    json_optional_str(value, key).filter(|value| !value.trim().is_empty())
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

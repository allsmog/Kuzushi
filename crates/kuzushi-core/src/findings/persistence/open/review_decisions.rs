use super::*;
use crate::storage_v3::writer_actor::{
    ControlCommand, DecisionCommand, DecisionWrite, StorageWriterActor, WriterCommand,
};

// Order decision reads by the projected row `id`, not `decision_event_seq`.
// The projection inserts decision rows in event-sequence order, so `id` is
// monotonic with `decision_event_seq` for backfilled rows yet is never NULL.
// Ordering by `id` therefore keeps sequenced decisions authoritative over
// wall-clock skew (as the event seq is) while still letting a later decision
// supersede a legacy row whose provenance backfill left `decision_event_seq`
// NULL. A leading `decision_event_seq` key cannot: SQLite sorts NULL below
// every value, so it would pin every NULL-provenance row to one extreme —
// permanently oldest (desc) or first (asc) — regardless of when it was recorded.
const LATEST_REVIEW_DECISIONS_SQL: &str = r#"
with requested as (
    select json_extract(value, '$.key') as lookup_key,
           json_extract(value, '$.identityId') as identity_id,
           cast(json_extract(value, '$.findingId') as integer) as finding_id
      from json_each(?1)
), ranked as (
    select requested.lookup_key,
           decisions.id, decisions.finding_id, decisions.identity_id,
           decisions.decision_verdict, decisions.triage_verdict,
           decisions.confidence, decisions.rationale, decisions.author,
           decisions.created_at, decisions.dismiss_reason, decisions.dismissed_by,
           decisions.decision_event_seq, decisions.decision_event_hash,
           decisions.decision_read_watermark,
           row_number() over (
               partition by requested.lookup_key
               order by decisions.id desc
           ) as decision_rank
      from requested
      join review_decisions as decisions
        on (requested.identity_id is not null and decisions.identity_id = requested.identity_id)
        or (requested.identity_id is null and decisions.finding_id = requested.finding_id)
     where ?2 = 0 or decisions.author = 'human'
)
select id, finding_id, identity_id, decision_verdict, triage_verdict,
       confidence, rationale, author, created_at, dismiss_reason, dismissed_by,
       decision_event_seq, decision_event_hash, decision_read_watermark, lookup_key
  from ranked
 where decision_rank = 1
"#;

const REVIEW_DECISIONS_FOR_FINDINGS_SQL: &str = r#"
with requested as (
    select json_extract(value, '$.identityId') as identity_id,
           cast(json_extract(value, '$.findingId') as integer) as finding_id
      from json_each(?1)
), matched as (
    select distinct decisions.id, decisions.finding_id, decisions.identity_id,
           decisions.decision_verdict, decisions.triage_verdict,
           decisions.confidence, decisions.rationale, decisions.author,
           decisions.created_at, decisions.dismiss_reason, decisions.dismissed_by,
           decisions.decision_event_seq, decisions.decision_event_hash,
           decisions.decision_read_watermark
      from requested
      join review_decisions as decisions
        on (requested.identity_id is not null and decisions.identity_id = requested.identity_id)
        or (requested.identity_id is null and decisions.finding_id = requested.finding_id)
)
select id, finding_id, identity_id, decision_verdict, triage_verdict,
       confidence, rationale, author, created_at, dismiss_reason, dismissed_by,
       decision_event_seq, decision_event_hash, decision_read_watermark
  from matched
 order by id asc
"#;

impl FindingStore {
    pub(crate) fn latest_review_decisions_for_findings(
        &self,
        findings: &[Finding],
        human_only: bool,
    ) -> Result<std::collections::BTreeMap<String, ReviewDecision>> {
        let requested = findings
            .iter()
            .filter_map(review_decision_request)
            .collect::<Vec<_>>();
        if requested.is_empty() {
            return Ok(std::collections::BTreeMap::new());
        }
        let requested = serde_json::to_string(&requested)?;
        let mut stmt = self.conn.prepare(LATEST_REVIEW_DECISIONS_SQL)?;
        let rows = stmt.query_map(params![requested, human_only as i64], |row| {
            Ok((
                row.get::<_, String>(14)?,
                review_decision_record_from_row(row)?.decision,
            ))
        })?;
        rows.collect::<rusqlite::Result<std::collections::BTreeMap<_, _>>>()
            .context("Could not batch latest review decisions")
    }

    pub fn list_review_decisions_for_findings(
        &self,
        findings: &[Finding],
    ) -> Result<Vec<ReviewDecisionRecord>> {
        let requested = findings
            .iter()
            .filter_map(review_decision_request)
            .collect::<Vec<_>>();
        if requested.is_empty() {
            return Ok(Vec::new());
        }
        let requested = serde_json::to_string(&requested)?;
        let mut stmt = self.conn.prepare(REVIEW_DECISIONS_FOR_FINDINGS_SQL)?;
        let rows = stmt.query_map(params![requested], review_decision_record_from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not batch review decisions")
    }

    pub fn list_review_decisions(&self, finding_id: i64) -> Result<Vec<ReviewDecisionRecord>> {
        let mut stmt = self.conn.prepare(
            r#"
            select id, finding_id, identity_id, decision_verdict, triage_verdict,
                   confidence, rationale, author, created_at, dismiss_reason, dismissed_by,
                   decision_event_seq, decision_event_hash, decision_read_watermark
              from review_decisions
             where finding_id = ?1
             order by id asc
            "#,
        )?;
        let rows = stmt.query_map(params![finding_id], review_decision_record_from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list review decisions")
    }

    pub fn list_review_decisions_for_identity(
        &self,
        identity_id: &str,
    ) -> Result<Vec<ReviewDecisionRecord>> {
        let mut stmt = self.conn.prepare(
            r#"
            select id, finding_id, identity_id, decision_verdict, triage_verdict,
                   confidence, rationale, author, created_at, dismiss_reason, dismissed_by,
                   decision_event_seq, decision_event_hash, decision_read_watermark
              from review_decisions
             where identity_id = ?1
             order by id asc
            "#,
        )?;
        let rows = stmt.query_map(params![identity_id], review_decision_record_from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list review decisions for identity")
    }

    pub fn list_review_decisions_for_finding_identity(
        &self,
        finding_id: i64,
    ) -> Result<Vec<ReviewDecisionRecord>> {
        let Some(identity_id) = self.identity_id_for_finding(finding_id)? else {
            return self.list_review_decisions(finding_id);
        };
        self.list_review_decisions_for_identity(&identity_id)
    }

    pub fn latest_review_decision(&self, finding_id: i64) -> Result<Option<ReviewDecisionRecord>> {
        let mut stmt = self.conn.prepare(
            r#"
            select id, finding_id, identity_id, decision_verdict, triage_verdict,
                   confidence, rationale, author, created_at, dismiss_reason, dismissed_by,
                   decision_event_seq, decision_event_hash, decision_read_watermark
              from review_decisions
             where finding_id = ?1
             order by id desc
             limit 1
            "#,
        )?;
        stmt.query_row(params![finding_id], review_decision_record_from_row)
            .optional()
            .context("Could not load latest review decision")
    }

    pub fn latest_review_decision_for_identity(
        &self,
        identity_id: &str,
    ) -> Result<Option<ReviewDecisionRecord>> {
        let mut stmt = self.conn.prepare(
            r#"
            select id, finding_id, identity_id, decision_verdict, triage_verdict,
                   confidence, rationale, author, created_at, dismiss_reason, dismissed_by,
                   decision_event_seq, decision_event_hash, decision_read_watermark
              from review_decisions
             where identity_id = ?1
             order by id desc
             limit 1
            "#,
        )?;
        stmt.query_row(params![identity_id], review_decision_record_from_row)
            .optional()
            .context("Could not load latest review decision for identity")
    }

    pub fn latest_review_decision_for_finding_identity(
        &self,
        finding_id: i64,
    ) -> Result<Option<ReviewDecisionRecord>> {
        let Some(identity_id) = self.identity_id_for_finding(finding_id)? else {
            return self.latest_review_decision(finding_id);
        };
        self.latest_review_decision_for_identity(&identity_id)
    }

    /// Most recent HUMAN-authored decision for a finding's identity. The triage
    /// fold must ignore a later automated re-triage so an LLM verdict cannot
    /// mask a human `Confirmed`/dismissal (which would flip a `Fixed` to
    /// `Removed`, or resurrect a dismissed finding).
    pub fn latest_human_review_decision_for_finding_identity(
        &self,
        finding_id: i64,
    ) -> Result<Option<ReviewDecisionRecord>> {
        let Some(identity_id) = self.identity_id_for_finding(finding_id)? else {
            return self.latest_human_review_decision(finding_id);
        };
        self.latest_human_review_decision_for_identity(&identity_id)
    }

    fn latest_human_review_decision(
        &self,
        finding_id: i64,
    ) -> Result<Option<ReviewDecisionRecord>> {
        let mut stmt = self.conn.prepare(
            r#"
            select id, finding_id, identity_id, decision_verdict, triage_verdict,
                   confidence, rationale, author, created_at, dismiss_reason, dismissed_by,
                   decision_event_seq, decision_event_hash, decision_read_watermark
              from review_decisions
             where finding_id = ?1 and author = 'human'
             order by id desc
             limit 1
            "#,
        )?;
        stmt.query_row(params![finding_id], review_decision_record_from_row)
            .optional()
            .context("Could not load latest human review decision")
    }

    fn latest_human_review_decision_for_identity(
        &self,
        identity_id: &str,
    ) -> Result<Option<ReviewDecisionRecord>> {
        let mut stmt = self.conn.prepare(
            r#"
            select id, finding_id, identity_id, decision_verdict, triage_verdict,
                   confidence, rationale, author, created_at, dismiss_reason, dismissed_by,
                   decision_event_seq, decision_event_hash, decision_read_watermark
              from review_decisions
             where identity_id = ?1 and author = 'human'
             order by id desc
             limit 1
            "#,
        )?;
        stmt.query_row(params![identity_id], review_decision_record_from_row)
            .optional()
            .context("Could not load latest human review decision for identity")
    }

    pub fn append_user_review_decision(
        &self,
        finding_id: i64,
        decision: &ReviewDecision,
    ) -> Result<i64> {
        if decision.author == TriageAuthor::Auto {
            anyhow::bail!(
                "append_user_review_decision requires a human or imported author; automated triage must use record_auto_triage"
            );
        }
        if decision.rationale.trim().is_empty() {
            anyhow::bail!("review decision reason cannot be empty");
        }
        self.append_review_decision(finding_id, decision, false)
    }

    /// Appends an immutable dismissal event through the existing single-writer
    /// actor. Rejects an empty note (same policy as `append_user_review_decision`).
    pub fn append_dismissal(
        &self,
        finding_id: i64,
        reason: DismissReason,
        note: &str,
        actor: &str,
    ) -> Result<i64> {
        if note.trim().is_empty() {
            anyhow::bail!("dismissal note cannot be empty");
        }
        let actor = if actor.trim().is_empty() {
            "operator"
        } else {
            actor.trim()
        };
        let decision = ReviewDecision::dismissal(reason, note.trim(), actor);
        self.append_review_decision(finding_id, &decision, false)
    }

    pub(in crate::findings::persistence::open) fn append_review_decision_from_triage(
        &self,
        finding_id: i64,
        triage: &TriageOutcome,
        author: TriageAuthor,
    ) -> Result<i64> {
        let decision = ReviewDecision::from_triage(triage, Some(author));
        self.append_review_decision_event(
            finding_id,
            &decision,
            true,
            Some((triage.cost_usd, triage.cost_usd_exact)),
        )
    }

    fn append_review_decision(
        &self,
        finding_id: i64,
        decision: &ReviewDecision,
        updates_finding_triage: bool,
    ) -> Result<i64> {
        self.append_review_decision_event(finding_id, decision, updates_finding_triage, None)
    }

    fn append_review_decision_event(
        &self,
        finding_id: i64,
        decision: &ReviewDecision,
        updates_finding_triage: bool,
        triage_cost: Option<(f64, bool)>,
    ) -> Result<i64> {
        let target = self
            .v3_target_for_finding(finding_id, "review decision")?
            .context("review decisions require a file-backed v3 finding identity")?;
        let read_watermark = StorageWriterActor::commit_blocking(
            target.event_log_dir.clone(),
            target.db_path.clone(),
            WriterCommand::Control(ControlCommand::Barrier),
        )?
        .committed_seq;
        let (triage_cost_usd, triage_cost_usd_exact) = triage_cost_payload(triage_cost)?;
        let write = DecisionWrite {
            stable_fp: target.stable_fp,
            finding_id: Some(finding_id),
            identity_id: target.identity_id,
            verdict: decision.verdict.as_str().to_string(),
            author: decision.author.as_str().to_string(),
            rationale: decision.rationale.clone(),
            confidence_millis: confidence_millis(decision.confidence),
            read_watermark,
            updates_finding_triage,
            triage_cost_usd,
            triage_cost_usd_exact,
            dismiss_reason: decision
                .dismiss_reason
                .map(|reason| reason.as_str().to_string()),
            dismissed_by: decision.actor.clone(),
        };
        commit_review_decision(target.event_log_dir, target.db_path, write)
    }

    fn identity_id_for_finding(&self, finding_id: i64) -> Result<Option<String>> {
        Ok(self
            .v3_finding_by_projected_id(finding_id)?
            .and_then(|finding| finding.identity_id))
    }
}

fn triage_cost_payload(cost: Option<(f64, bool)>) -> Result<(Option<serde_json::Number>, bool)> {
    let Some((cost_usd, exact)) = cost else {
        return Ok((None, true));
    };
    anyhow::ensure!(
        cost_usd.is_finite() && cost_usd >= 0.0,
        "triage provider cost must be finite and non-negative"
    );
    let number = serde_json::Number::from_f64(cost_usd)
        .context("triage provider cost could not be represented in event JSON")?;
    Ok((Some(number), exact))
}

fn commit_review_decision(
    event_log_dir: std::path::PathBuf,
    db_path: std::path::PathBuf,
    write: DecisionWrite,
) -> Result<i64> {
    let receipt = StorageWriterActor::commit_blocking(
        event_log_dir,
        db_path,
        WriterCommand::Decision(DecisionCommand::ReviewDecision(write)),
    )?;
    Ok(receipt
        .projected_review_decision_id
        .unwrap_or(receipt.committed_seq as i64))
}

fn review_decision_request(finding: &Finding) -> Option<serde_json::Value> {
    finding
        .identity_id
        .as_ref()
        .map(|identity_id| {
            serde_json::json!({
                "key": format!("identity:{identity_id}"),
                "identityId": identity_id,
                "findingId": finding.id,
            })
        })
        .or_else(|| {
            finding.id.map(|finding_id| {
                serde_json::json!({
                    "key": format!("finding:{finding_id}"),
                    "identityId": null,
                    "findingId": finding_id,
                })
            })
        })
}

fn confidence_millis(confidence: f32) -> u16 {
    (confidence.clamp(0.0, 1.0) * 1000.0).round() as u16
}

fn review_decision_provenance_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Option<ReviewDecisionProvenance>> {
    let event_seq: Option<i64> = row.get(11)?;
    let event_hash: Option<String> = row.get(12)?;
    let (Some(event_seq), Some(event_hash)) = (event_seq, event_hash) else {
        return Ok(None);
    };
    let read_watermark: Option<i64> = row.get(13)?;
    Ok(Some(ReviewDecisionProvenance {
        event_seq: sql_row_u64(event_seq, "decision event seq")?,
        event_hash,
        read_watermark: read_watermark
            .map(|value| sql_row_u64(value, "decision read watermark"))
            .transpose()?,
    }))
}

fn sql_row_u64(value: i64, label: &str) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| to_sql_error(anyhow::anyhow!("negative {label}: {value}")))
}

fn review_decision_record_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<ReviewDecisionRecord> {
    let decision_verdict: String = row.get(3)?;
    let triage_verdict: Option<String> = row.get(4)?;
    let author: String = row.get(7)?;
    let dismiss_reason: Option<String> = row.get(9)?;
    let dismissed_by: Option<String> = row.get(10)?;
    Ok(ReviewDecisionRecord {
        id: row.get(0)?,
        finding_id: row.get(1)?,
        identity_id: row.get(2)?,
        decision: ReviewDecision {
            verdict: ReviewDecisionVerdict::from_str(&decision_verdict).ok_or_else(|| {
                to_sql_error(anyhow::anyhow!(
                    "unknown review decision verdict {decision_verdict:?}"
                ))
            })?,
            author: TriageAuthor::from_str(&author).ok_or_else(|| {
                to_sql_error(anyhow::anyhow!("unknown review decision author {author:?}"))
            })?,
            confidence: row.get(5)?,
            rationale: row.get(6)?,
            dismiss_reason: dismiss_reason.as_deref().and_then(DismissReason::from_str),
            actor: dismissed_by,
        },
        triage_verdict: triage_verdict
            .as_deref()
            .map(TriageVerdict::try_from)
            .transpose()
            .map_err(to_sql_error)?,
        created_at: row.get(8)?,
        provenance: review_decision_provenance_from_row(row)?,
    })
}

use super::*;
use crate::findings::persistence::lesson_reads;
use crate::storage_v3::writer_actor::{DecisionCommand, StorageWriterActor, WriterCommand};

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingLessonPage {
    pub rows: Vec<FindingLesson>,
    pub offset: usize,
    pub has_more: bool,
}

impl FindingStore {
    pub(crate) fn lesson_observation(&self, origin: &LessonOrigin) -> Result<Finding> {
        validate_lesson_origin(&self.conn, origin)?;
        let raw: String = self.conn.query_row(
            "select finding_json from finding_observations where stable_fp=?1 and created_seq=?2",
            params![
                origin.finding.stable_key,
                i64::try_from(origin.observation_seq)?
            ],
            |row| row.get(0),
        )?;
        serde_json::from_str(&raw).context("Lesson observation is malformed")
    }

    pub fn finding_lesson(&self, id: &str) -> Result<Option<FindingLesson>> {
        lesson_reads::latest(&self.conn, id)
    }

    pub fn finding_lesson_revision(&self, reference: &LessonRef) -> Result<FindingLesson> {
        lesson_reads::exact(&self.conn, reference)
    }

    pub fn finding_lessons(&self, limit: usize, offset: usize) -> Result<FindingLessonPage> {
        anyhow::ensure!(
            (1..=200).contains(&limit) && offset <= 1_000_000,
            "Invalid lesson page limit or offset"
        );
        let mut rows = lesson_reads::page(&self.conn, limit + 1, offset)?;
        let has_more = rows.len() > limit;
        rows.truncate(limit);
        Ok(FindingLessonPage {
            rows,
            offset,
            has_more,
        })
    }

    pub fn lesson_origin(&self, target: &Path, finding_id: i64) -> Result<LessonOrigin> {
        let finding = self
            .get_finding_by_reference(&format!("generation:{finding_id}"))?
            .context("Lesson finding generation is missing")?;
        let decision = self
            .latest_human_review_decision_for_finding_identity(finding_id)?
            .context("Confirm this finding before drafting a lesson")?;
        let watermark = decision
            .provenance
            .as_ref()
            .and_then(|p| p.read_watermark)
            .context("Confirmation has no source watermark")?;
        let stable_key = finding
            .identity_id
            .clone()
            .unwrap_or_else(|| finding.fingerprint.clone());
        let snapshot = self
            .observed_snapshot_at(&stable_key, watermark)?
            .context("Confirmed observation is missing")?;
        let source_git =
            crate::run_artifacts::load_run_summary_without_repair(target, &snapshot.run_id)
                .ok()
                .and_then(|summary| summary.target_git);
        let origin = LessonOrigin {
            target: target.canonicalize()?.to_string_lossy().into_owned(),
            finding: FindingRelationshipEndpoint {
                stable_key,
                fingerprint: finding.fingerprint,
                finding_id,
                run_id: Some(snapshot.run_id),
            },
            decision,
            observation_seq: snapshot.created_seq,
            snapshot_hash: snapshot.snapshot_hash,
            source_git,
        };
        validate_lesson_origin(&self.conn, &origin)?;
        Ok(origin)
    }

    pub fn draft_finding_lesson(
        &self,
        content: LessonContent,
        origin: LessonOrigin,
        generation: Option<LessonGeneration>,
    ) -> Result<FindingLesson> {
        let record = FindingLesson::draft(
            format!("lesson_{}", uuid::Uuid::new_v4()),
            content,
            origin,
            generation,
        )?;
        self.commit_lesson(&record, None)?;
        Ok(record)
    }

    pub fn revise_finding_lesson(
        &self,
        reference: &LessonRef,
        content: LessonContent,
    ) -> Result<FindingLesson> {
        let record = self
            .finding_lesson_revision(reference)?
            .revise(reference, content)?;
        self.commit_lesson(&record, Some(reference))?;
        Ok(record)
    }

    pub fn review_finding_lesson(
        &self,
        reference: &LessonRef,
        state: LessonState,
        note: String,
    ) -> Result<FindingLesson> {
        let record = self
            .finding_lesson_revision(reference)?
            .review(reference, state, note)?;
        self.commit_lesson(&record, Some(reference))?;
        Ok(record)
    }

    pub fn accepted_finding_lesson(&self, reference: &LessonRef) -> Result<FindingLesson> {
        let record = self.finding_lesson_revision(reference)?;
        anyhow::ensure!(
            record.state == LessonState::Accepted,
            "Only accepted lessons can enter context"
        );
        anyhow::ensure!(
            self.finding_lesson(&record.id)?.as_ref() == Some(&record),
            "Lesson changed or was retired; review its latest revision"
        );
        validate_lesson_origin(&self.conn, &record.origin)?;
        Ok(record)
    }

    fn commit_lesson(&self, record: &FindingLesson, expected: Option<&LessonRef>) -> Result<()> {
        let (log, db) = self.required_v3_storage_paths("finding lesson")?;
        StorageWriterActor::commit_blocking(
            log,
            db,
            WriterCommand::Decision(DecisionCommand::FindingLesson {
                record: record.clone(),
                expected: expected.cloned(),
            }),
        )?;
        Ok(())
    }
}

pub(crate) fn validate_lesson_origin(conn: &Connection, origin: &LessonOrigin) -> Result<()> {
    origin.validate()?;
    let current = read_current_human_confirmation(conn, origin)?;
    anyhow::ensure!(
        current.as_ref() == Some(&origin.decision),
        "Finding confirmation changed; reassess the lesson origin"
    );
    let (raw,run,snapshot): (String,String,String)=conn.query_row(
        "select finding_json,run_id,snapshot_hash from finding_observations where stable_fp=?1 and created_seq=?2",
        params![origin.finding.stable_key,i64::try_from(origin.observation_seq)?],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    ).optional()?.context("Lesson observation is missing")?;
    let finding: Finding = serde_json::from_str(&raw)?;
    anyhow::ensure!(
        finding.id == Some(origin.finding.finding_id)
            && finding.fingerprint == origin.finding.fingerprint
            && origin.finding.run_id.as_deref() == Some(&run)
            && origin.snapshot_hash == snapshot,
        "Lesson origin does not match the recorded generation"
    );
    Ok(())
}

fn read_current_human_confirmation(
    conn: &Connection,
    origin: &LessonOrigin,
) -> Result<Option<ReviewDecisionRecord>> {
    conn.query_row(
        "select id,finding_id,identity_id,decision_verdict,triage_verdict,confidence,rationale,author,created_at,dismiss_reason,dismissed_by,decision_event_seq,decision_event_hash,decision_read_watermark from review_decisions
         where author='human' and ((?1 is not null and identity_id=?1) or (identity_id is null and finding_id=?2)) order by id desc limit 1",
        params![origin.decision.identity_id,origin.finding.finding_id],review_decisions::review_decision_record_from_row,
    ).optional().context("Could not authenticate lesson confirmation")
}

#[cfg(test)]
mod tests;

//! Serialize lesson revision checks and their single audit event under the writer lock.
use super::*;
use crate::findings::{FindingLesson, LessonRef, LessonState, FINDING_LESSON_SUBJECT};

impl StorageWriter {
    pub(super) fn record_finding_lesson(
        &mut self,
        record: FindingLesson,
        expected: Option<LessonRef>,
    ) -> Result<WriteReceipt> {
        require_state(self.lifecycle.state(), WriterActorState::Live)?;
        record.validate()?;
        let current =
            crate::findings::persistence::lesson_reads::latest(&self.projection.conn, &record.id)?;
        validate_transition(current.as_ref(), &record, expected.as_ref())?;
        if matches!(record.state, LessonState::Draft | LessonState::Accepted) {
            crate::findings::persistence::validate_lesson_origin(
                &self.projection.conn,
                &record.origin,
            )?;
        }
        self.record_audit_event(AuditWrite {
            event_kind: EventKind::DiagnosticRecorded,
            actor: record.author.clone(),
            run_id: None,
            stable_fp: Some(record.origin.finding.stable_key.clone()),
            subject: Some(FINDING_LESSON_SUBJECT.into()),
            summary: format!("Lesson {:?}: {}", record.state, record.content.title),
            details: serde_json::to_value(record)?,
        })
    }
}

fn validate_transition(
    current: Option<&FindingLesson>,
    next: &FindingLesson,
    expected: Option<&LessonRef>,
) -> Result<()> {
    let Some(current) = current else {
        anyhow::ensure!(
            expected.is_none() && next.revision == 1 && next.state == LessonState::Draft,
            "New lesson must be a draft at revision 1"
        );
        return Ok(());
    };
    anyhow::ensure!(
        expected == Some(&current.reference()?),
        "Lesson changed; refresh before deciding"
    );
    anyhow::ensure!(
        next.id == current.id
            && next.origin == current.origin
            && next.generation == current.generation,
        "Lesson origin or generation receipt changed"
    );
    anyhow::ensure!(
        next.revision
            == current
                .revision
                .checked_add(1)
                .context("Lesson revision exhausted")?,
        "Invalid lesson revision"
    );
    if next.state != LessonState::Draft {
        anyhow::ensure!(
            next.content == current.content,
            "Review cannot change lesson content"
        );
    }
    Ok(())
}

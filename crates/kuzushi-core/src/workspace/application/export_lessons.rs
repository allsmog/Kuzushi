//! Export historical lessons without changing their acceptance or finding verdicts.
use super::export_projection_model::WorkspaceFindingExportRecord;
use super::*;
use crate::findings::{FindingLesson, LessonRef};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceLessonExportRecord {
    pub lesson_ref: LessonRef,
    pub lesson: FindingLesson,
    pub eligible_for_context: bool,
    pub eligibility_note: String,
}

pub(super) fn attach_lessons(
    store: &FindingStore,
    findings: &[Finding],
    records: &mut [WorkspaceFindingExportRecord],
) -> Result<()> {
    let watermark = store.projection_meta()?.applied_seq;
    let generations = findings
        .iter()
        .filter_map(|finding| finding.id.map(|id| (id, finding.fingerprint.as_str())))
        .collect::<HashMap<_, _>>();
    let mut lessons = export_lessons(store, &generations)?;
    for record in records {
        record.lessons = lessons
            .remove(record.fingerprint.as_str())
            .unwrap_or_default();
    }
    anyhow::ensure!(
        store.projection_meta()?.applied_seq == watermark,
        "Lesson decisions changed during export; refresh before exporting"
    );
    Ok(())
}

fn export_lessons(
    store: &FindingStore,
    generations: &HashMap<i64, &str>,
) -> Result<HashMap<String, Vec<WorkspaceLessonExportRecord>>> {
    let mut selected = HashMap::<String, Vec<WorkspaceLessonExportRecord>>::new();
    let mut offset = 0;
    loop {
        let page = store.finding_lessons(200, offset)?;
        for lesson in page.rows {
            attach_selected_lesson(store, generations, &mut selected, lesson)?;
        }
        if !page.has_more {
            return Ok(selected);
        }
        offset += 200;
    }
}

fn attach_selected_lesson(
    store: &FindingStore,
    generations: &HashMap<i64, &str>,
    selected: &mut HashMap<String, Vec<WorkspaceLessonExportRecord>>,
    lesson: FindingLesson,
) -> Result<()> {
    let Some(fingerprint) = generations.get(&lesson.origin.finding.finding_id) else {
        return Ok(());
    };
    anyhow::ensure!(
        *fingerprint == lesson.origin.finding.fingerprint,
        "Lesson origin fingerprint differs from its exported generation"
    );
    selected
        .entry((*fingerprint).into())
        .or_default()
        .push(lesson_export_record(store, lesson)?);
    Ok(())
}

fn lesson_export_record(
    store: &FindingStore,
    lesson: FindingLesson,
) -> Result<WorkspaceLessonExportRecord> {
    let lesson_ref = lesson.reference()?;
    let eligibility = store.accepted_finding_lesson(&lesson_ref);
    let eligibility_note = match &eligibility {
        Ok(_) => "Accepted historical guidance. Other source revisions require independent review."
            .into(),
        Err(error) => {
            format!("Unavailable for context: {error}. Historical text remains in this export.")
        }
    };
    Ok(WorkspaceLessonExportRecord {
        lesson_ref,
        lesson,
        eligible_for_context: eligibility.is_ok(),
        eligibility_note,
    })
}

pub(super) fn push_markdown_lessons(out: &mut String, lessons: &[WorkspaceLessonExportRecord]) {
    if lessons.is_empty() {
        return;
    }
    out.push_str("## Reusable lessons\n\nHistorical guidance is separate from finding verdicts and applicability at other source revisions. The exact current lesson records follow.\n\n");
    for lesson in lessons {
        // Indented JSON preserves every field and keeps target text inert in Markdown.
        let serialized =
            serde_json::to_string_pretty(lesson).expect("lesson export is serializable");
        for line in serialized.lines() {
            out.push_str(&format!("    {line}\n"));
        }
        out.push('\n');
    }
}

#[cfg(test)]
mod tests;

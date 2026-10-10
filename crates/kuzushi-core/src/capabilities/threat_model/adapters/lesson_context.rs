//! Select reviewed lessons into a new inactive immutable context copy.
use super::*;
use crate::findings::LessonRef;

pub(crate) fn reuse_lessons_adapter(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let root = workspace_root(ctx, "threat-model:reuse-lessons")?;
    context_edit::require_selected_context_target(root, &input, ctx)?;
    let reference = context_edit::edit_reference(&input)?;
    let records = selected_lessons(root, &input, ctx)?;
    let mut document = load_exact_threat_model(root, &reference)?;
    let object = document
        .as_object_mut()
        .context("Context must be an object")?;
    object.remove("verification");
    object.insert("userEdited".into(), json!(true));
    object.insert("reviewedLessons".into(), serde_json::to_value(&records)?);
    object.insert("lessonSelection".into(),json!({"schemaVersion":1,"sourceModelRef":reference,"actor":"operator","count":records.len()}));
    let mut request = context_edit::edit_commit_request(root, &reference, input.get("label"))?;
    request.actor = "tool:threat-model:reuse-lessons".into();
    let committed = ctx.with_cancellation(|cancel| {
        commit_threat_model_revision_cancellable(root, &document, request, &|| {
            cancel.is_cancelled()
        })
    })?;
    Ok(crate::module_result::completed_output_result(
        "Saved an inactive context copy with the selected reviewed lessons.",
        "Saved an inactive context copy. Inspect and explicitly select it before scanning.",
        json!({"sourceModelRef":reference,"modelRef":committed.model_ref,"document":document,"activated":false,"lessonCount":records.len()}),
    ))
}

fn selected_lessons(
    root: &Path,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Vec<crate::findings::FindingLesson>> {
    let references: Vec<LessonRef> = serde_json::from_value(input["lessons"].clone())
        .context("lessons must contain exact lesson references")?;
    anyhow::ensure!(
        references.len() <= 8,
        "Select at most eight lessons per context copy"
    );
    let store = ctx
        .findings_store
        .context("Lesson selection requires the findings store")?;
    let mut ids = std::collections::BTreeSet::new();
    let target = root.canonicalize()?.to_string_lossy().into_owned();
    references
        .iter()
        .map(|reference| {
            anyhow::ensure!(
                ids.insert(&reference.lesson_id),
                "A lesson was selected more than once"
            );
            let record = store.accepted_finding_lesson(reference)?;
            anyhow::ensure!(
                record.origin.target == target,
                "Lesson belongs to a different workspace"
            );
            Ok(record)
        })
        .collect()
}

#[cfg(test)]
mod tests;

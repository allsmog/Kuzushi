//! One bounded defensive lesson draft, with human acceptance kept separate.
use crate::findings::{FindingLesson, LessonContent, LessonGeneration, LessonOrigin};
use crate::{modules::ToolExecutionContext, runtime::AgentRuntime};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
mod sources;
mod synthesis;
pub(crate) use sources::inspect as read_source_evidence;
#[cfg(test)]
mod tests;

pub(crate) fn prepare_generation_input(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let origin = selected_origin(input, ctx)?;
    let mut prepared = input.clone();
    prepared
        .as_object_mut()
        .context("Lesson input must be an object")?
        .insert("originRef".into(), serde_json::to_value(&origin)?);
    sources::prepare(&mut prepared, &origin, ctx)?;
    Ok(prepared)
}

pub(crate) fn validate_generation_input(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    let origin = selected_origin(input, ctx)?;
    sources::load(input, &origin, ctx).map(|_| ())
}

fn selected_origin(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<LessonOrigin> {
    let root = ctx.workspace.context("Select a lesson target")?.root();
    let id = input["findingId"]
        .as_i64()
        .context("Select an exact finding generation")?;
    let origin = read_origin(root, id, ctx)?;
    if let Some(reference) = input.get("originRef") {
        let expected: LessonOrigin =
            serde_json::from_value(reference.clone()).context("Invalid lesson origin reference")?;
        anyhow::ensure!(
            expected == origin,
            "Lesson origin changed; prepare a new draft before spending"
        );
    }
    let guidance = input["guidance"].as_str().unwrap_or_default();
    anyhow::ensure!(guidance.len() <= 2048, "Lesson guidance exceeds 2048 bytes");
    Ok(origin)
}

fn read_origin(
    root: &std::path::Path,
    id: i64,
    ctx: &ToolExecutionContext<'_>,
) -> Result<LessonOrigin> {
    if let Some(store) = ctx.findings_store {
        return store.lesson_origin(root, id);
    }
    let workspace = crate::WorkspaceTarget::new(root)?;
    crate::FindingStore::open_read_only(workspace.findings_db_path())?.lesson_origin(root, id)
}

pub(crate) fn execute_generate(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    ctx.ensure_active()?;
    let origin = selected_origin(input, ctx)?;
    let runtime = runtime.context("Lesson generation requires the selected model runtime")?;
    let generated = synthesis::request(input, &origin, ctx, runtime)?;
    ctx.ensure_active()?;
    let record = ctx.findings_store.unwrap().draft_finding_lesson(
        generated.content,
        origin,
        Some(generated.receipt),
    )?;
    lesson_output(record)
}

fn lesson_output(record: FindingLesson) -> Result<Value> {
    Ok(crate::module_result::completed_output_result(
        "Saved a model-proposed lesson draft. Human review and context selection remain separate.",
        "Saved a model-proposed lesson draft. Inspect its evidence and limitations before accepting it.",
        json!({"lessonRef":record.reference()?,"lesson":record,"accepted":false}),
    ))
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LessonResponse {
    schema_version: u32,
    content: LessonContent,
}

struct GeneratedLesson {
    content: LessonContent,
    receipt: LessonGeneration,
}

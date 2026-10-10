use super::*;
use crate::modules::ToolExecutionContext;
use serde_json::{json, Value};

pub fn execute_brief(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    ctx.ensure_active()?;
    let root = ctx
        .workspace
        .context("Investigation brief requires a workspace")?
        .root();
    let id = input["briefId"].as_str().unwrap_or("repository");
    let revision = match input["mode"].as_str().unwrap_or("read") {
        "read" => read(root, id, input)?,
        "save" => Some(save(root, id, input, ctx)?),
        _ => anyhow::bail!("Unsupported investigation brief mode"),
    };
    let output = revision.as_ref().map_or_else(
        || "No saved investigation brief. Enter a goal, priorities and open questions; review before saving. No work or allowance is approved.".into(),
        render);
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({"target":root,"brief":revision,"workApproved":false,"modelRequests":0,"findingVerdictsChanged":false}),
    ))
}

fn read(root: &Path, id: &str, input: &Value) -> Result<Option<BriefRevision>> {
    anyhow::ensure!(
        input.get("text").is_none() && input.get("expectedRevision").is_none(),
        "Read mode does not save text or revisions"
    );
    let Some(value) = input.get("briefRef") else {
        return load_current_brief(root, id);
    };
    let reference =
        serde_json::from_value(value.clone()).context("Brief reference is malformed")?;
    load_brief(root, &reference).map(Some)
}

fn save(
    root: &Path,
    id: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<BriefRevision> {
    anyhow::ensure!(
        input.get("briefRef").is_none(),
        "Save mode uses expectedRevision rather than briefRef"
    );
    let expected = u32::try_from(
        input["expectedRevision"]
            .as_u64()
            .context("Save requires expectedRevision")?,
    )?;
    let text = input["text"].as_str().context("Save requires brief text")?;
    super::save_brief(root, id, expected, text, &|| ctx.is_cancelled())
}

fn render(brief: &BriefRevision) -> String {
    format!("Investigation brief · {} · revision {}\nOperator intent for planning and priorities. This is not source evidence or a finding verdict. Saving approves no work or allowance and changes no model context.\n\n{}\n\nReference: {}", brief.reference.brief_id, brief.reference.revision, brief.document.text, brief.reference.object.hash)
}

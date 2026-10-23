//! Supported one-model Map actions share the existing fixed campaign contract.
use super::*;

pub(super) const SCOPE_TOOL: &str = "pack:suggest-scopes";
pub(super) const REGENERATE_TOOL: &str = "threat-model:regenerate";
pub(super) const LESSON_TOOL: &str = "findings:lesson-generate";
pub(super) const QUESTION_TOOL: &str = "threat-model:ask";
pub(super) const PLANNER_TOOL: &str = "planner:propose";

pub(super) fn default_tool() -> String {
    TOOL.into()
}

pub(super) fn selected(value: Option<&str>) -> Result<&'static str> {
    match value {
        None | Some(TOOL) => Ok(TOOL),
        Some(SCOPE_TOOL) => Ok(SCOPE_TOOL),
        Some(REGENERATE_TOOL) => Ok(REGENERATE_TOOL),
        Some(LESSON_TOOL) => Ok(LESSON_TOOL),
        Some(QUESTION_TOOL) => Ok(QUESTION_TOOL),
        Some(PLANNER_TOOL) => Ok(PLANNER_TOOL),
        _ => anyhow::bail!("unsupported Map generation tool"),
    }
}

pub(super) fn prepare(
    tool: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    registry: &ModuleRegistry,
) -> Result<Value> {
    if tool == TOOL {
        return super::input::prepare(input, ctx, registry);
    }
    anyhow::ensure!(
        matches!(
            tool,
            SCOPE_TOOL | REGENERATE_TOOL | LESSON_TOOL | QUESTION_TOOL | PLANNER_TOOL
        ),
        "unsupported Map generation tool"
    );
    validate(tool, input)?;
    let mut draft = if tool == PLANNER_TOOL {
        crate::capabilities::planner::prepare_input(input, registry)?
    } else {
        input.clone()
    };
    let object = draft
        .as_object_mut()
        .context("contextInput must be an object")?;
    // This is shape validation only. The placeholder is removed before freezing
    // and never reaches dispatch, approval, accounting or a model runtime.
    object.insert("allowanceRef".into(), json!({"schemaVersion":1,"investigationId":"planning-only","revision":1,"workId":"planning-only"}));
    let prepared = registry.prepare_dispatch_input(tool, draft, ctx, None)?;
    let mut frozen = prepared.value().clone();
    frozen.as_object_mut().unwrap().remove("allowanceRef");
    let model = crate::tool_execution_model(tool, &frozen, ctx.config)
        .context("Select a model before planning scope suggestions")?;
    frozen["model"] = json!(model);
    if tool == LESSON_TOOL {
        return crate::capabilities::finding_lessons::prepare_generation_input(&frozen, ctx);
    }
    validate_selected_input(tool, &frozen, ctx)?;
    Ok(frozen)
}

fn validate_selected_input(
    tool: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    if tool == PLANNER_TOOL {
        return crate::capabilities::planner::validate_input(input);
    }
    validate_existing_generation_input(tool, input, ctx)
}

fn validate_existing_generation_input(
    tool: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    if tool == LESSON_TOOL {
        return crate::capabilities::finding_lessons::validate_generation_input(input, ctx);
    }
    if tool == REGENERATE_TOOL {
        return crate::capabilities::threat_model::validate_context_regeneration_input(input, ctx);
    }
    if tool == QUESTION_TOOL {
        return crate::capabilities::threat_model::validate_context_question_input(input, ctx);
    }
    crate::workspace::validate_scan_scope_suggestion_input(input, ctx)
}

pub(super) fn validate(tool: &str, input: &Value) -> Result<()> {
    if tool == TOOL {
        return super::input::validate(input);
    }
    anyhow::ensure!(
        matches!(
            tool,
            SCOPE_TOOL | REGENERATE_TOOL | LESSON_TOOL | QUESTION_TOOL | PLANNER_TOOL
        ),
        "unsupported Map generation tool"
    );
    anyhow::ensure!(input.is_object() && input.get("allowanceRef").is_none(),
        "Map generation input must be an object without an allowance; approve its frozen job separately");
    Ok(())
}

pub(super) fn validate_preparation(
    tool: &str,
    input: &Value,
    jobs: &[ContextPreparationJob],
) -> Result<()> {
    anyhow::ensure!(
        (tool == TOOL && input.get("scanScopeRef").is_none() && input.get("sourcePaths").is_none()) || jobs.is_empty(),
        "Scope suggestions, file-group context, selected-text regeneration and lesson drafts permit no additional preparation jobs"
    );
    Ok(())
}

pub fn scope_proposal_study_input(
    root: &Path,
    reference: crate::workspace::ScanScopeProposalRef,
    priorities: String,
    omit_context: bool,
) -> Result<Value> {
    use crate::capabilities::threat_model::ThreatModelSelection;
    anyhow::ensure!(
        priorities.len() <= 2048,
        "scope priorities exceed 2048 bytes"
    );
    let context = if omit_context {
        Value::Null
    } else {
        match crate::workflow_attempts::accepted_map_context_selection(root)? {
            ThreatModelSelection::Revision(reference) => json!(reference),
            _ => Value::Null,
        }
    };
    Ok(json!({"proposalRef":reference,"priorities":priorities,"threatModelRef":context}))
}

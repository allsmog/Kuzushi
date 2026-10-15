//! Goal relevance has no model, finding verdict or workflow completion effect.
use super::*;
use crate::capabilities::campaign::{
    load_brief, load_current_brief, BriefReference, BriefRevision,
};
use crate::findings::{FindingGoalAssessment, FindingGoalBasis, GoalRelevance};
use crate::WorkspaceTarget;

pub(crate) fn tools() -> Vec<ToolDescriptor> {
    vec![
        goal_tool("findings:goals", "Browse findings by operator-assessed relevance to an exact saved brief. Priorities never determine finding verdicts.", vec![
            opt("briefId", OptionType::String, "Saved brief to open when briefRef is absent.").default(json!("repository")),
            opt("briefRef", OptionType::Json, "Exact saved brief revision. Reading never follows a newer head when this is supplied."),
            opt("filter", OptionType::Enum, "Goal relevance view. Changed observations are unassessed.").choices(&["all","unassessed","direct","related","outside","uncertain"]).default(json!("all")),
            opt("limit", OptionType::Int, "Findings per page.").integer_range(1,200).default(json!(50)),
            opt("offset", OptionType::Int, "Goal review page offset.").integer_range(0,1_000_000).default(json!(0)),
            opt("findingId", OptionType::Int, "Read the complete relevance history for this exact finding generation instead of a page.").integer_range(1,i64::MAX),
        ], ToolEffect::Read),
        goal_tool("findings:goal-assess", "Record, replace or clear an operator goal assessment. Saves history; changes no finding truth, confidence, severity or decisions.", vec![
            opt("briefRef", OptionType::Json, "Exact published brief reviewed by the operator.").required(),
            opt("basis", OptionType::Json, "Exact finding observation basis from findings:goals.").required(),
            opt("relevance", OptionType::Enum, "Relationship to the reviewed goal; clear removes the active assessment while retaining history.").choices(&["direct","related","outside","uncertain","cleared"]).required(),
            opt("reason", OptionType::String, "Operator reason, from 1 to 4096 bytes.").required(),
            opt("expectedRevision", OptionType::Int, "Assessment revision shown when reviewed, zero if unassessed.").integer_range(0,i64::MAX).required(),
        ], ToolEffect::WorkspaceWrite),
    ]
}

fn goal_tool(
    name: &str,
    description: &str,
    options: Vec<OptionSpec>,
    effect: ToolEffect,
) -> ToolDescriptor {
    tool_with_options(name, description, options)
        .with_policy(tool_policy(
            ToolPhase::Review,
            RuntimeRequirement::Never,
            effect,
            WorkspaceRequirement::Required,
            FindingStoreRequirement::Required,
        ))
        .without_phase_result()
}

pub(crate) fn execute(name: &str, input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let store = ctx
        .findings_store
        .context("Goal review requires the findings store")?;
    let workspace = ctx.workspace.context("Select a goal review target")?;
    ctx.ensure_active()?;
    if name == "findings:goal-assess" {
        return save(store, workspace, input);
    }
    if let Some(id) = input["findingId"].as_i64() {
        return Ok(
            json!({"ok":true,"output":"Historical goal assessments; finding decisions remain separate","data":{"history":store.finding_goal_history(id)?}}),
        );
    }
    let mut page = crate::findings::read_goals(
        store,
        resolve_brief(workspace, input)?,
        input["offset"].as_u64().unwrap_or(0) as usize,
        input["limit"].as_u64().unwrap_or(50) as usize,
        input["filter"].as_str().unwrap_or("all"),
        &|| ctx.ensure_active().is_err(),
    )?;
    load_source_receipts(workspace, &mut page);
    Ok(
        json!({"ok":true,"output":"Goal relevance is operator priority, separate from finding truth. Source changes require reassessment.","data":page}),
    )
}

fn resolve_brief(workspace: &WorkspaceTarget, input: &Value) -> Result<Option<BriefRevision>> {
    if let Some(reference) = input.get("briefRef") {
        return load_brief(
            workspace.root(),
            &serde_json::from_value(reference.clone())?,
        )
        .map(Some);
    }
    load_current_brief(
        workspace.root(),
        input["briefId"].as_str().unwrap_or("repository"),
    )
}

fn save(store: &FindingStore, workspace: &WorkspaceTarget, input: &Value) -> Result<Value> {
    let brief_ref: BriefReference = serde_json::from_value(input["briefRef"].clone())?;
    let brief = load_brief(workspace.root(), &brief_ref)?;
    let basis: FindingGoalBasis = serde_json::from_value(input["basis"].clone())?;
    let relevance: GoalRelevance = serde_json::from_value(input["relevance"].clone())?;
    let expected = input["expectedRevision"]
        .as_u64()
        .context("Assessment revision is required")?;
    let record = FindingGoalAssessment {
        schema_version: 1,
        id: FindingGoalAssessment::key(&brief_ref, basis.finding_id),
        revision: expected
            .checked_add(1)
            .context("Assessment revision exhausted")?,
        brief_text: brief.document.text,
        brief_ref,
        basis,
        relevance,
        reason: input["reason"]
            .as_str()
            .context("Add a goal relevance reason")?
            .trim()
            .into(),
        author: "operator".into(),
        recorded_at: crate::findings::now_isoish(),
    };
    record.validate()?;
    store.save_goal_assessment(&record, expected)?;
    Ok(
        json!({"ok":true,"output":"Goal relevance saved. Finding verdicts and confidence are unchanged.","data":record}),
    )
}

fn load_source_receipts(workspace: &WorkspaceTarget, page: &mut crate::findings::FindingGoalPage) {
    let mut runs = std::collections::BTreeMap::new();
    for row in &mut page.rows {
        let git = runs.entry(row.basis.run_id.clone()).or_insert_with(|| {
            crate::run_artifacts::load_run_summary_without_repair(
                workspace.root(),
                &row.basis.run_id,
            )
            .ok()
            .and_then(|run| run.target_git)
        });
        row.source_git = git.clone();
    }
}

#[cfg(test)]
mod tests;

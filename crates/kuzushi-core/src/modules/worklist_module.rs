use super::*;
use crate::capabilities::worklist::{
    rank_worklist_for_target, Worklist, WorklistOptions, WorklistRow,
};

pub(crate) fn worklist_module() -> BuiltinModule {
    builtin_module(
        "worklist",
        "Worklist",
        ModuleKind::Intel,
        "Risk-ranked file worklist folded from deterministic rankers: attack surface, \
         scan-coverage recommendations, and an opt-in systems-hunt walk. No model calls; \
         every row carries each contributing ranker's raw evidence.",
        vec![worklist_rank_tool()
            .with_policy(read_policy(ToolPhase::Map, WorkspaceRequirement::Required))
            .without_phase_result()],
        vec![],
    )
}

fn worklist_rank_tool() -> ToolDescriptor {
    tool_with_options(
        "worklist:rank",
        "Rank the highest-risk files by folding attack-surface risk, scan-coverage \
         recommendations, and optionally a Read-safe systems-hunt walk. Deterministic: no \
         model calls and no implicit graph builds. Every row cites each ranker's raw value.",
        vec![
            opt("limit", OptionType::Int, "Maximum ranked rows to return.")
                .default(json!(20))
                .integer_range(1, 500),
            opt(
                "deep",
                OptionType::Bool,
                "Also walk the production inventory with the systems-hunt surface scorer. \
                 Stays Read-safe (no graph build) but reads more files.",
            )
            .default(json!(false)),
            opt(
                "includeFanIn",
                OptionType::Bool,
                "Call-graph fan-in is not implemented. Requesting it is an error; defaults off.",
            )
            .aliases(&["include_fan_in", "fanIn"])
            .default(json!(false)),
            target_option(),
        ],
    )
}

pub(in crate::modules) fn run_worklist_rank(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context("worklist:rank requires an active workspace target")?;
    let options = worklist_options(input);
    let target = crate::WorkspaceTarget::new(resolve_tool_target(input, ctx)?)?;
    let child_store = worklist_child_store(&target, workspace)?;
    let store = if target.root() == workspace.root() {
        ctx.findings_store
    } else {
        child_store.as_ref()
    };
    let worklist = rank_worklist_for_target(target.root(), &options, store)?;
    let output = worklist_output_line(&worklist);
    let mut data = serde_json::to_value(&worklist)?;
    data["target"] = json!(target.root());
    data["sourceFreshnessVerified"] = json!(false);
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        data,
    ))
}

fn worklist_child_store(
    target: &crate::WorkspaceTarget,
    workspace: &crate::WorkspaceTarget,
) -> Result<Option<crate::findings::FindingStore>> {
    if target.root() == workspace.root() {
        return Ok(None);
    }
    let path = target.findings_db_path();
    match std::fs::symlink_metadata(&path) {
        Ok(_) => crate::findings::FindingStore::open_read_only(path).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("Could not inspect selected target findings store"),
    }
}

fn worklist_options(input: &Value) -> WorklistOptions {
    WorklistOptions {
        limit: worklist_limit(input),
        deep: worklist_flag(input, "deep", false),
        include_fan_in: worklist_flag(input, "includeFanIn", false),
    }
}

fn worklist_limit(input: &Value) -> usize {
    input
        .get("limit")
        .and_then(Value::as_u64)
        .map(|limit| limit as usize)
        .filter(|limit| *limit > 0)
        .unwrap_or(20)
}

fn worklist_flag(input: &Value, key: &str, default: bool) -> bool {
    input.get(key).and_then(Value::as_bool).unwrap_or(default)
}

fn worklist_output_line(worklist: &Worklist) -> String {
    let summary = match worklist.rows.first() {
        Some(top) => format!(
            "worklist:rank · {} of {} ranked file(s) shown · top: {} ({})",
            worklist.rows.len(),
            worklist.ranked_total,
            top.path,
            top_row_evidence(top),
        ),
        None => "worklist:rank · no ranked files; run context:build first".to_string(),
    };
    if worklist.degraded.is_empty() {
        return summary;
    }
    format!(
        "{summary} · {} contributor issue(s); inspect result details",
        worklist.degraded.len()
    )
}

/// A bare normalized `score {:.2}` launders the evidence. Report the top row's
/// raw per-contributor displays (e.g. `A 92/100 · C scan sink-gap`) so the
/// one-liner cites the same raw values as the deck.
fn top_row_evidence(row: &WorklistRow) -> String {
    if row.citations.is_empty() {
        return format!("score {:.2}", row.score);
    }
    row.citations
        .iter()
        .map(|citation| format!("{} {}", citation.contributor.glyph(), citation.raw_display))
        .collect::<Vec<_>>()
        .join(" · ")
}

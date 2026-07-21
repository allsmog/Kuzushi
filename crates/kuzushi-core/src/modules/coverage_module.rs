use super::*;
use crate::workspace::coverage_ledger::{
    sweep_target, write_sweep_skips, CoverageLedger, SweepReport, SweepVerdict,
};

pub(crate) fn coverage_module() -> BuiltinModule {
    builtin_module(
        "coverage",
        "Coverage Ledger",
        ModuleKind::Intel,
        "Receipt-backed scan coverage: per-scope baselines and a deterministic staleness sweep.",
        vec![
            coverage_sweep_tool().with_policy(workspace_policy(
                ToolPhase::Map,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Optional,
            )),
            coverage_baselines_tool().with_policy(read_policy(
                ToolPhase::Map,
                WorkspaceRequirement::Required,
            )),
            coverage_recommend_tool().with_policy(read_policy(
                ToolPhase::Map,
                WorkspaceRequirement::Required,
            )),
        ],
        vec![],
    )
}

fn coverage_sweep_tool() -> ToolDescriptor {
    tool_with_options(
        "coverage:sweep",
        "Decide per scope and phase whether the target changed since its recorded scan \
         baseline. Verdicts: changed, current, or baseline-unreachable. Diffs are always \
         whole-repo, never pathspec-limited.",
        vec![opt(
            "writeSkips",
            OptionType::Bool,
            "Advance unchanged baselines to HEAD by recording sweep-skip rows. \
             Refused on a dirty tree.",
        )
        .aliases(&["write_skips", "write-skips"])
        .default(json!(false))],
    )
}

fn coverage_baselines_tool() -> ToolDescriptor {
    tool(
        "coverage:baselines",
        "List recorded scan baselines (latest per scope and phase) from the coverage ledger.",
    )
}

fn coverage_recommend_tool() -> ToolDescriptor {
    tool_with_options(
        "coverage:recommend",
        "Rank scope-level scan recommendations from deterministic signals: coverage gaps, \
         staleness since baselines, surface-dense files with zero findings, and saturation. \
         No model calls; every row carries its mechanical evidence.",
        vec![opt(
            "limit",
            OptionType::Int,
            "Maximum recommendations to return.",
        )
        .default(json!(20))],
    )
}

pub(in crate::modules) fn run_coverage_sweep(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context("coverage:sweep requires an active workspace target")?;
    let report = sweep_target(workspace.root())?;
    let skips_written = if write_skips_requested(input) {
        Some(write_sweep_skips(workspace.root(), &report)?)
    } else {
        None
    };
    let output = sweep_output_line(&report, skips_written);
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({ "report": report, "skipsWritten": skips_written }),
    ))
}

pub(in crate::modules) fn run_coverage_baselines(ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context("coverage:baselines requires an active workspace target")?;
    let baselines = match CoverageLedger::open_if_exists(workspace.root())? {
        Some(ledger) => ledger.latest_baselines()?,
        None => Vec::new(),
    };
    let output = format!(
        "coverage:baselines · {} baseline(s) recorded",
        baselines.len()
    );
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({ "baselines": baselines.iter().map(baseline_json).collect::<Vec<_>>() }),
    ))
}

pub(in crate::modules) fn run_coverage_recommend(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context("coverage:recommend requires an active workspace target")?;
    let limit = recommend_limit(input);
    let recommendations = crate::capabilities::scan_recommender::recommend_scans_for_target(
        workspace.root(),
        ctx.findings_store,
    )?;
    let shown: Vec<_> = recommendations.iter().take(limit).collect();
    let output = recommend_output_line(&recommendations, shown.len());
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({ "recommendations": shown }),
    ))
}

fn recommend_limit(input: &Value) -> usize {
    input
        .get("limit")
        .and_then(Value::as_u64)
        .map(|limit| limit as usize)
        .filter(|limit| *limit > 0)
        .unwrap_or(20)
}

fn recommend_output_line(
    recommendations: &[crate::capabilities::scan_recommender::ScanRecommendation],
    shown: usize,
) -> String {
    match recommendations.first() {
        Some(top) => format!(
            "coverage:recommend · {shown} of {} recommendation(s) · top: {} {} ({}) — {}",
            recommendations.len(),
            top.scope_id,
            top.phase.word(),
            top.reason.label(),
            top.evidence,
        ),
        None => "coverage:recommend · nothing to recommend".to_string(),
    }
}

fn write_skips_requested(input: &Value) -> bool {
    input
        .get("writeSkips")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn sweep_output_line(report: &SweepReport, skips_written: Option<usize>) -> String {
    let counts = verdict_counts(report);
    let skips = skips_written
        .map(|written| format!(" · {written} skip row(s) written"))
        .unwrap_or_default();
    format!(
        "coverage:sweep · head {} · {} changed · {} current · {} unreachable · {} never-scanned{skips}",
        short_sha(&report.head.sha),
        counts.changed,
        counts.current,
        counts.unreachable,
        report.unbaselined_scopes.len(),
    )
}

struct VerdictCounts {
    changed: usize,
    current: usize,
    unreachable: usize,
}

fn verdict_counts(report: &SweepReport) -> VerdictCounts {
    let mut counts = VerdictCounts {
        changed: 0,
        current: 0,
        unreachable: 0,
    };
    for entry in &report.entries {
        match entry.verdict {
            SweepVerdict::Changed { .. } => counts.changed += 1,
            SweepVerdict::Current => counts.current += 1,
            SweepVerdict::BaselineUnreachable => counts.unreachable += 1,
        }
    }
    counts
}

fn short_sha(sha: &str) -> &str {
    sha.get(..8).unwrap_or(sha)
}

fn baseline_json(row: &crate::workspace::coverage_ledger::BaselineRow) -> Value {
    json!({
        "scopeId": row.scope_id,
        "phase": row.phase.word(),
        "mode": row.mode,
        "runId": row.run_id,
        "revisionSha": row.revision.sha,
        "branch": row.revision.branch,
        "dirty": row.revision.dirty,
        "tsUnix": row.ts_unix,
    })
}

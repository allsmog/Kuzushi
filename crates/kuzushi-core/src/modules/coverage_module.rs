use super::*;
use crate::workspace::coverage_ledger::{
    sweep_target_with_cancellation, write_sweep_skips_with_cancellation, CoverageLedger,
    SweepReport, SweepVerdict,
};

pub(crate) fn coverage_module() -> BuiltinModule {
    builtin_module(
        "coverage",
        "Coverage Ledger",
        ModuleKind::Intel,
        "Historical Git baselines and explicit source-staleness checks. These records alone do not establish complete scan coverage.",
        vec![
            coverage_sweep_tool()
                .with_policy(workspace_policy(
                    ToolPhase::Operate,
                    RuntimeRequirement::Never,
                    FindingStoreRequirement::Optional,
                ))
                .without_phase_result(),
            coverage_baselines_tool()
                .with_policy(read_policy(
                    ToolPhase::Operate,
                    WorkspaceRequirement::Required,
                ))
                .without_phase_result(),
            coverage_recommend_tool()
                .with_policy(read_policy(
                    ToolPhase::Operate,
                    WorkspaceRequirement::Required,
                ))
                .without_phase_result(),
        ],
        vec![],
    )
}

fn coverage_sweep_tool() -> ToolDescriptor {
    tool_with_options(
        "coverage:sweep",
        "Inspect historical Git baselines. Dirty sources and unavailable scopes remain unverified. Unchanged tracked source does not establish complete scan coverage or a fixed finding. Diffs are whole-repository.",
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
         staleness since baselines, and surface-dense files with zero findings. \
         No model calls; every row carries its mechanical evidence.",
        vec![opt(
            "limit",
            OptionType::Int,
            "Maximum recommendations to return.",
        )
        .default(json!(20))
        .integer_range(1, 500)],
    )
}

pub(in crate::modules) fn run_coverage_sweep(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context("coverage:sweep requires an active workspace target")?;
    let report = sweep_target_with_cancellation(workspace.root(), ctx.cancellation)?;
    let skips_written = if write_skips_requested(input) {
        Some(write_sweep_skips_with_cancellation(
            workspace.root(),
            &report,
            ctx.cancellation,
        )?)
    } else {
        None
    };
    let output = sweep_output_line(&report, skips_written);
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({ "report": report, "skipsWritten": skips_written,
            "sourceMeaning":"historical-git-baseline-check", "scopeCoverageVerified":false, "findingFixVerified":false }),
    ))
}

pub(in crate::modules) fn run_coverage_baselines(ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    ctx.ensure_active()?;
    let workspace = ctx
        .workspace
        .context("coverage:baselines requires an active workspace target")?;
    let baselines = match CoverageLedger::open_if_exists(workspace.root())? {
        Some(ledger) => ledger.latest_baselines_with_cancellation(ctx.cancellation)?,
        None => Vec::new(),
    };
    let output = baseline_output(&baselines);
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({ "baselines": baselines.iter().map(baseline_json).collect::<Vec<_>>(),
            "sourceMeaning":"historical-git-baseline-records", "scopeCoverageVerified":false }),
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
        json!({ "recommendations": shown, "recommendationTotal": recommendations.len(),
            "target": workspace.root(), "sourceFreshnessVerified":false,
            "sourceMeaning":"advisory-persisted-context-and-historical-baselines" }),
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
            "coverage:recommend · {shown} of {} recommendation(s) · top: {} {} ({}) · {}",
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
        "Historical Git baseline check\nHEAD: {} · {}\n{} changed · {} source unchanged · {} unreachable · {} source unverified · {} without a baseline{skips}\n{}\nUnchanged tracked source does not establish complete scan coverage or a fixed finding.",
        report.head.sha,
        if report.head.dirty { "dirty" } else { "clean" },
        counts.changed,
        counts.current,
        counts.unreachable,
        counts.unverified,
        report.unbaselined_scopes.len(),
        report.entries.iter().map(sweep_entry_output).collect::<Vec<_>>().join("\n"),
    )
}

struct VerdictCounts {
    changed: usize,
    current: usize,
    unreachable: usize,
    unverified: usize,
}

fn verdict_counts(report: &SweepReport) -> VerdictCounts {
    VerdictCounts {
        changed: report
            .entries
            .iter()
            .filter(|entry| matches!(entry.verdict, SweepVerdict::Changed { .. }))
            .count(),
        current: report
            .entries
            .iter()
            .filter(|entry| entry.verdict == SweepVerdict::Current)
            .count(),
        unreachable: report
            .entries
            .iter()
            .filter(|entry| entry.verdict == SweepVerdict::BaselineUnreachable)
            .count(),
        unverified: report
            .entries
            .iter()
            .filter(|entry| matches!(entry.verdict, SweepVerdict::SourceUnverified { .. }))
            .count(),
    }
}

fn sweep_entry_output(entry: &crate::workspace::coverage_ledger::ScopeSweepEntry) -> String {
    format!(
        "{} · {} · {}\n  baseline: {}",
        entry.scope_id,
        entry.phase.word(),
        sweep_verdict_label(entry.verdict),
        entry.baseline_sha,
    )
}

fn sweep_verdict_label(verdict: SweepVerdict) -> String {
    match verdict {
        SweepVerdict::Changed { files } => format!("source changed: {files} file(s)"),
        SweepVerdict::Current => "tracked source unchanged".into(),
        SweepVerdict::BaselineUnreachable => "baseline unreachable".into(),
        SweepVerdict::SourceUnverified { reason } => {
            format!("source unverified: {}", source_issue_label(reason))
        }
    }
}

fn source_issue_label(issue: crate::workspace::coverage_ledger::SourceCheckIssue) -> &'static str {
    use crate::workspace::coverage_ledger::SourceCheckIssue;
    match issue {
        SourceCheckIssue::DirtyWorkingTree => "working tree is dirty",
        SourceCheckIssue::DirtyBaseline => "baseline was captured dirty",
        SourceCheckIssue::ScopeUnavailable => "scope is unavailable",
    }
}

fn baseline_output(rows: &[crate::workspace::coverage_ledger::BaselineRow]) -> String {
    let records = rows
        .iter()
        .map(|row| {
            format!(
                "{} · {} · {} · run {}\n  commit: {}",
                row.scope_id,
                row.phase.word(),
                if row.revision.dirty { "dirty" } else { "clean" },
                row.run_id,
                row.revision.sha,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!("Historical Git baseline records: {}\n{records}\nRun summaries alone do not establish complete scope coverage.", rows.len())
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

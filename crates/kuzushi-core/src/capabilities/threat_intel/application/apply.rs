use crate::capabilities::threat_intel::adapters::load_catalog_from_path;
use crate::capabilities::threat_intel::application::dispatch::{plan_for_entry, DispatchPlan};
use crate::modules::ToolExecutionContext;
use crate::runtime::AgentRuntime;
use anyhow::Result;
use serde_json::{json, Value};
use std::path::Path;

#[cfg(test)]
mod receipt_tests;

pub(crate) fn catalog_dispatch_requested(input: &Value) -> bool {
    input.get("dryRun").and_then(Value::as_bool) == Some(false)
}

/// Apply a threat-intel catalog: load the TOML, route each entry to
/// the right hunt, return a per-entry result with the dispatch
/// outcome and (when live execution is in scope) the resulting
/// findings count.
///
/// `dispatch_live` controls whether to actually run the hunts or to
/// just plan them. `false` is useful as a dry run / sanity check;
/// `true` invokes the hunts via the supplied dispatcher closure (the
/// closure is passed in instead of called inline because the
/// `ModuleRegistry::execute_tool_with_runtime` lives in
/// `crates/kuzushi-core/src/modules/registry/`, and threading the
/// registry through here would create a circular dependency).
pub fn apply_threat_intel_catalog(
    catalog_path: &Path,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    dispatch_live: bool,
    dispatch_tool: impl FnMut(
        &str,
        Value,
        &ToolExecutionContext<'_>,
        Option<&dyn AgentRuntime>,
    ) -> Result<Value>,
) -> Result<Value> {
    let entries = load_catalog_from_path(catalog_path)?;
    let parent_step =
        emit_threat_intel_apply_start(ctx, catalog_path, entries.len(), dispatch_live);
    let applied = apply_threat_intel_entries(
        &entries,
        ctx,
        runtime,
        dispatch_live,
        dispatch_tool,
        parent_step,
    );
    emit_threat_intel_apply_done(ctx, &applied.stats);
    Ok(threat_intel_apply_response(
        catalog_path,
        entries.len(),
        applied.results,
        applied.stats,
        !dispatch_live,
    ))
}

struct ThreatIntelApplyResult {
    results: Vec<Value>,
    stats: ThreatIntelApplyStats,
}

fn apply_threat_intel_entries(
    entries: &[crate::capabilities::threat_intel::domain::CatalogEntry],
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    dispatch_live: bool,
    mut dispatch_tool: impl FnMut(
        &str,
        Value,
        &ToolExecutionContext<'_>,
        Option<&dyn AgentRuntime>,
    ) -> Result<Value>,
    parent_step: Option<crate::run_lifecycle::RunItemId>,
) -> ThreatIntelApplyResult {
    let mut applied = ThreatIntelApplyResult {
        results: Vec::with_capacity(entries.len()),
        stats: ThreatIntelApplyStats::default(),
    };
    let _dispatch_scope = begin_threat_intel_apply_scope(ctx, parent_step);
    for entry in entries {
        emit_threat_intel_apply_entry(ctx, parent_step, entry);
        apply_threat_intel_entry(
            entry,
            ctx,
            runtime,
            dispatch_live,
            &mut dispatch_tool,
            &mut applied.stats,
            &mut applied.results,
        );
    }
    applied
}

fn emit_threat_intel_apply_entry(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<crate::run_lifecycle::RunItemId>,
    entry: &crate::capabilities::threat_intel::domain::CatalogEntry,
) {
    emit_threat_intel_apply_progress(
        ctx,
        parent_step,
        format!("entry · {} · {}", entry.id, entry.hunt.as_str()),
    );
}

fn emit_threat_intel_apply_start(
    ctx: &ToolExecutionContext<'_>,
    catalog_path: &Path,
    entry_count: usize,
    dispatch_live: bool,
) -> Option<crate::run_lifecycle::RunItemId> {
    ctx.trace.map(|trace| {
        let mode = if dispatch_live { "live" } else { "dry-run" };
        trace
            .step(
                "tool",
                "apply",
                format!(
                    "threat-intel:apply start · {entry_count} entries · {mode} · {}",
                    catalog_path.display()
                ),
            )
            .emit()
    })
}

fn emit_threat_intel_apply_progress(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<crate::run_lifecycle::RunItemId>,
    label: impl Into<String>,
) {
    let (Some(trace), Some(parent)) = (ctx.trace, parent_step) else {
        return;
    };
    let _ = trace
        .child(parent)
        .step("tool-progress", "apply", label.into())
        .emit();
}

fn begin_threat_intel_apply_scope(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<crate::run_lifecycle::RunItemId>,
) -> Option<crate::run_artifacts::ParentScope> {
    let (Some(trace), Some(parent)) = (ctx.trace, parent_step) else {
        return None;
    };
    let phase = trace
        .child(parent)
        .step("reasoning", "apply", "dispatch catalog hunts")
        .emit();
    Some(trace.parent_scope(phase))
}

fn emit_threat_intel_apply_done(ctx: &ToolExecutionContext<'_>, stats: &ThreatIntelApplyStats) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "apply",
                format!(
                    "threat-intel:apply complete · {} dispatched · {} skipped · {} failed",
                    stats.dispatched, stats.skipped, stats.failed
                ),
            )
            .emit();
    }
}

#[derive(Default)]
struct ThreatIntelApplyStats {
    dispatched: u32,
    skipped: u32,
    failed: u32,
    partial: u32,
    dispatch_requests: u32,
    total_findings: u64,
}

fn apply_threat_intel_entry(
    entry: &crate::capabilities::threat_intel::domain::CatalogEntry,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    dispatch_live: bool,
    dispatch_tool: &mut impl FnMut(
        &str,
        Value,
        &ToolExecutionContext<'_>,
        Option<&dyn AgentRuntime>,
    ) -> Result<Value>,
    stats: &mut ThreatIntelApplyStats,
    results: &mut Vec<Value>,
) {
    match plan_for_entry(entry) {
        DispatchPlan::Dispatched { tool_name, input } if dispatch_live => {
            apply_live_threat_intel_entry(
                entry,
                tool_name,
                input,
                ctx,
                runtime,
                dispatch_tool,
                stats,
                results,
            );
        }
        DispatchPlan::Dispatched { tool_name, input } => {
            stats.dispatched += 1;
            results.push(planned_threat_intel_entry(entry, tool_name, input));
        }
        DispatchPlan::Skipped { reason } => {
            stats.skipped += 1;
            results.push(skipped_threat_intel_entry(entry, reason));
        }
    }
}

fn apply_live_threat_intel_entry(
    entry: &crate::capabilities::threat_intel::domain::CatalogEntry,
    tool_name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    dispatch_tool: &mut impl FnMut(
        &str,
        Value,
        &ToolExecutionContext<'_>,
        Option<&dyn AgentRuntime>,
    ) -> Result<Value>,
    stats: &mut ThreatIntelApplyStats,
    results: &mut Vec<Value>,
) {
    stats.dispatch_requests += 1;
    match dispatch_tool(tool_name, input.clone(), ctx, runtime) {
        Ok(result) => record_threat_intel_dispatch(entry, tool_name, input, result, stats, results),
        Err(err) => {
            record_threat_intel_dispatch_failure(entry, tool_name, input, err, stats, results)
        }
    }
}

fn record_threat_intel_dispatch(
    entry: &crate::capabilities::threat_intel::domain::CatalogEntry,
    tool_name: &str,
    input: Value,
    result: Value,
    stats: &mut ThreatIntelApplyStats,
    results: &mut Vec<Value>,
) {
    let count = extract_findings_count(&result);
    stats.total_findings += count;
    let status = record_child_outcome(stats, crate::module_result::tool_result_status(&result));
    results.push(json!({
        "id": entry.id,
        "status": status,
        "tool": tool_name,
        "input": input,
        "findingsCount": count,
        "tool_result": result,
    }));
}

fn record_child_outcome(
    stats: &mut ThreatIntelApplyStats,
    outcome: crate::module_result::ToolResultStatus,
) -> &'static str {
    use crate::module_result::ToolResultStatus;
    if outcome == ToolResultStatus::Failed {
        stats.failed += 1;
        return "dispatch-failed";
    }
    if outcome == ToolResultStatus::Skipped {
        stats.skipped += 1;
        return "skipped";
    }
    stats.dispatched += 1;
    if outcome == ToolResultStatus::Partial {
        stats.partial += 1;
        return "partial";
    }
    "dispatched"
}

fn record_threat_intel_dispatch_failure(
    entry: &crate::capabilities::threat_intel::domain::CatalogEntry,
    tool_name: &str,
    input: Value,
    err: anyhow::Error,
    stats: &mut ThreatIntelApplyStats,
    results: &mut Vec<Value>,
) {
    stats.failed += 1;
    results.push(json!({
        "id": entry.id,
        "status": "dispatch-failed",
        "tool": tool_name,
        "input": input,
        "error": format!("{err:#}"),
    }));
}

fn planned_threat_intel_entry(
    entry: &crate::capabilities::threat_intel::domain::CatalogEntry,
    tool_name: &str,
    input: Value,
) -> Value {
    json!({
        "id": entry.id,
        "status": "planned",
        "tool": tool_name,
        "input": input,
    })
}

fn skipped_threat_intel_entry(
    entry: &crate::capabilities::threat_intel::domain::CatalogEntry,
    reason: String,
) -> Value {
    json!({
        "id": entry.id,
        "status": "skipped",
        "hunt": entry.hunt.as_str(),
        "reason": reason,
    })
}

fn threat_intel_apply_response(
    catalog_path: &Path,
    total_entries: usize,
    entries: Vec<Value>,
    stats: ThreatIntelApplyStats,
    dry_run: bool,
) -> Value {
    let summary = json!({
        "totalEntries": total_entries,
        "dispatched": stats.dispatched,
        "skipped": stats.skipped,
        "failed": stats.failed,
        "partial": stats.partial,
        "planned": if dry_run { stats.dispatched } else { 0 },
        "dispatchRequests": stats.dispatch_requests,
        "totalFindings": stats.total_findings,
        "dryRun": dry_run,
    });
    let text = catalog_apply_summary(&stats, total_entries, dry_run);
    let data = json!({
        "catalogPath": catalog_path.display().to_string(),
        "entries": entries,
        "summary": summary,
    });
    catalog_apply_envelope(text, data, &stats)
}

fn catalog_apply_summary(stats: &ThreatIntelApplyStats, total: usize, dry_run: bool) -> String {
    if dry_run {
        return format!("threat-intel:apply planned {} of {total} entries · {} skipped. Preview only; no hunts started.", stats.dispatched, stats.skipped);
    }
    format!(
        "threat-intel:apply dispatched {} of {total} entries · {} skipped · {} failed · {} partial",
        stats.dispatched, stats.skipped, stats.failed, stats.partial
    )
}

fn catalog_apply_envelope(text: String, data: Value, stats: &ThreatIntelApplyStats) -> Value {
    if stats.failed == 0 && stats.partial == 0 {
        return crate::module_result::completed_output_result(text.clone(), text, data);
    }
    if stats.dispatched == 0 {
        return crate::module_result::failed_output_result(text.clone(), text, data);
    }
    crate::module_result::partial_output_result(text.clone(), text,
        vec![json!("Catalog dispatch is incomplete. Read each entry's result before approving further work.")], data)
}

pub fn list_threat_intel_catalog(catalog_path: &Path) -> Result<Value> {
    let entries = load_catalog_from_path(catalog_path)?;
    let rows: Vec<Value> = entries
        .iter()
        .map(|entry| {
            json!({
                "id": entry.id,
                "cves": entry.cves,
                "title": entry.title,
                "cwe": entry.cwe,
                "severity": entry.severity.as_str(),
                "hunt": entry.hunt.as_str(),
                "provenance": entry.provenance,
                "fixCommit": entry.fix_commit,
            })
        })
        .collect();
    Ok(threat_intel_list_response(catalog_path, rows))
}

fn threat_intel_list_response(catalog_path: &Path, entries: Vec<Value>) -> Value {
    let total_entries = entries.len();
    let summary = json!({ "totalEntries": total_entries });
    let text = format!(
        "threat-intel:list loaded {} entr{}",
        total_entries,
        if total_entries == 1 { "y" } else { "ies" }
    );
    let data = json!({
        "catalogPath": catalog_path.display().to_string(),
        "entries": entries,
        "summary": summary,
    });
    crate::module_result::completed_output_result(text.clone(), text, data)
}

fn extract_findings_count(result: &Value) -> u64 {
    result
        .get("summary")
        .and_then(|s| s.get("count"))
        .and_then(Value::as_u64)
        .or_else(|| {
            result
                .get("data")
                .and_then(|d| d.get("count"))
                .and_then(Value::as_u64)
        })
        .unwrap_or(0)
}

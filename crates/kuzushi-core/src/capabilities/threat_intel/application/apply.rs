use crate::capabilities::threat_intel::adapters::load_catalog_from_path;
use crate::capabilities::threat_intel::application::dispatch::{plan_for_entry, DispatchPlan};
use crate::modules::ToolExecutionContext;
use crate::runtime::AgentRuntime;
use anyhow::Result;
use serde_json::{json, Value};
use std::path::Path;

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
    mut dispatch_tool: impl FnMut(
        &str,
        Value,
        &ToolExecutionContext<'_>,
        Option<&dyn AgentRuntime>,
    ) -> Result<Value>,
) -> Result<Value> {
    let entries = load_catalog_from_path(catalog_path)?;
    let mut results = Vec::with_capacity(entries.len());
    let mut stats = ThreatIntelApplyStats::default();

    for entry in &entries {
        apply_threat_intel_entry(
            entry,
            ctx,
            runtime,
            dispatch_live,
            &mut dispatch_tool,
            &mut stats,
            &mut results,
        );
    }
    Ok(threat_intel_apply_response(
        catalog_path,
        entries.len(),
        results,
        stats,
        !dispatch_live,
    ))
}

#[derive(Default)]
struct ThreatIntelApplyStats {
    dispatched: u32,
    skipped: u32,
    failed: u32,
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
            apply_live_threat_intel_entry(entry, tool_name, input, ctx, runtime, dispatch_tool, stats, results);
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
    match dispatch_tool(tool_name, input.clone(), ctx, runtime) {
        Ok(result) => record_threat_intel_dispatch(entry, tool_name, input, result, stats, results),
        Err(err) => record_threat_intel_dispatch_failure(entry, tool_name, input, err, stats, results),
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
    stats.dispatched += 1;
    results.push(json!({
        "id": entry.id,
        "status": "dispatched",
        "tool": tool_name,
        "input": input,
        "findingsCount": count,
        "tool_result": result,
    }));
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
        "totalFindings": stats.total_findings,
        "dryRun": dry_run,
    });
    let text = format!(
        "threat-intel:apply {} {} of {} entr{}",
        if dry_run { "planned" } else { "dispatched" },
        stats.dispatched,
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

#[path = "harvest_entry.rs"]
mod harvest_entry;
#[path = "harvest_input.rs"]
mod harvest_input;
#[path = "harvest_render.rs"]
mod harvest_render;
#[path = "harvest_result.rs"]
mod harvest_result;

use self::harvest_entry::{
    harvest_one, HarvestedCatalogEntry, HarvestedEntry,
};
use self::harvest_input::{parse_cve_list, resolve_output_path};
use self::harvest_render::{render_catalog_toml, write_catalog_with_append};
use self::harvest_result::{harvest_result, HarvestGateConfig, HarvestStats};
use crate::capabilities::threat_intel::application::regression_gate::{
    run_regression_gate, RegressionGateOutcome, RegressionGateStatus,
};
use crate::modules::ToolExecutionContext;
use crate::runtime::AgentRuntime;
use anyhow::Result;
use serde_json::{json, Value};
use std::path::Path;

/// Harvest a threat-intel catalog by walking a list of CVE IDs and
/// converting each one's fix-commit context into a catalog entry.
///
/// Pipeline per CVE:
///   1. `ndiff:fetch-cve` pulls the advisory and patch references.
///   2. `ndiff:extract-fix-pattern` extracts fix-diff source, sink,
///      sanitizer, and detection-query signals.
///   3. The harvester serializes the pattern as operator-reviewable TOML.
pub fn harvest_threat_intel_catalog(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    mut dispatch_tool: impl FnMut(
        &str,
        Value,
        &ToolExecutionContext<'_>,
        Option<&dyn AgentRuntime>,
    ) -> Result<Value>,
) -> Result<Value> {
    let cves = parse_cve_list(input)?;
    let output_path = resolve_output_path(input, ctx)?;
    let gate = harvest_gate_config(input, ctx);
    let mut per_cve = Vec::with_capacity(cves.len());
    let mut new_entries = Vec::new();
    let mut stats = HarvestStats::default();

    for cve in &cves {
        harvest_cve_into_catalog(
            cve,
            ctx,
            runtime,
            &mut dispatch_tool,
            &gate,
            &mut stats,
            &mut per_cve,
            &mut new_entries,
        );
    }

    let toml_text = render_catalog_toml(&new_entries, &output_path)?;
    write_catalog_with_append(&output_path, &toml_text)?;

    Ok(harvest_result(
        &output_path,
        per_cve,
        cves.len(),
        &stats,
        &gate,
    ))
}

fn harvest_gate_config(input: &Value, ctx: &ToolExecutionContext<'_>) -> HarvestGateConfig {
    HarvestGateConfig {
        enabled: input
            .get("regressionGate")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        accept_rejected: input
            .get("acceptRejected")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        target: ctx.workspace.map(|w| w.root().to_path_buf()),
    }
}

fn harvest_cve_into_catalog(
    cve: &str,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    dispatch_tool: &mut impl FnMut(
        &str,
        Value,
        &ToolExecutionContext<'_>,
        Option<&dyn AgentRuntime>,
    ) -> Result<Value>,
    gate: &HarvestGateConfig,
    stats: &mut HarvestStats,
    per_cve: &mut Vec<Value>,
    new_entries: &mut Vec<HarvestedCatalogEntry>,
) {
    match harvest_one(cve, ctx, runtime, dispatch_tool) {
        Ok(HarvestedEntry::Entry(entry)) => {
            record_harvested_entry(cve, entry, gate, stats, per_cve, new_entries);
        }
        Ok(HarvestedEntry::Skipped { reason }) => record_skipped_cve(cve, reason, stats, per_cve),
        Err(err) => record_failed_cve(cve, err, stats, per_cve),
    }
}

fn record_skipped_cve(
    cve: &str,
    reason: String,
    stats: &mut HarvestStats,
    per_cve: &mut Vec<Value>,
) {
    stats.skipped += 1;
    per_cve.push(json!({"cve": cve, "status": "skipped", "reason": reason}));
}

fn record_failed_cve(
    cve: &str,
    err: anyhow::Error,
    stats: &mut HarvestStats,
    per_cve: &mut Vec<Value>,
) {
    stats.failed += 1;
    per_cve.push(json!({
        "cve": cve,
        "status": "failed",
        "error": format!("{err:#}"),
    }));
}

fn record_harvested_entry(
    cve: &str,
    mut entry: HarvestedCatalogEntry,
    gate: &HarvestGateConfig,
    stats: &mut HarvestStats,
    per_cve: &mut Vec<Value>,
    new_entries: &mut Vec<HarvestedCatalogEntry>,
) {
    let gate_outcome = harvest_gate_outcome(gate, cve, &entry);
    record_gate_stats(stats, gate_outcome.as_ref());
    if let Some(outcome) = &gate_outcome {
        entry.gate_outcome = Some(outcome.clone());
    }
    if harvest_rejected_by_gate(gate, gate_outcome.as_ref()) {
        stats.skipped += 1;
        per_cve.push(rejected_gate_row(cve, gate_outcome.as_ref()));
        return;
    }
    stats.harvested += 1;
    per_cve.push(harvested_entry_row(cve, &entry, gate_outcome));
    new_entries.push(entry);
}

fn harvest_gate_outcome(
    gate: &HarvestGateConfig,
    cve: &str,
    entry: &HarvestedCatalogEntry,
) -> Option<RegressionGateOutcome> {
    if !gate.enabled {
        return None;
    }
    Some(match gate.target.as_deref() {
        Some(target) => {
            gate_outcome_or_unverified(target, cve, &entry.fetched_record, &entry.fetched_pattern)
        }
        None => RegressionGateOutcome::unverified(
            "no workspace target available; pass --target <repo> to enable the regression gate"
                .to_string(),
        ),
    })
}

fn record_gate_stats(stats: &mut HarvestStats, outcome: Option<&RegressionGateOutcome>) {
    match outcome.map(|outcome| &outcome.status) {
        Some(RegressionGateStatus::Validated) => stats.validated_by_gate += 1,
        Some(RegressionGateStatus::Unverified) => stats.unverified_by_gate += 1,
        Some(RegressionGateStatus::Rejected) => stats.rejected_by_gate += 1,
        None => {}
    }
}

fn harvest_rejected_by_gate(
    gate: &HarvestGateConfig,
    outcome: Option<&RegressionGateOutcome>,
) -> bool {
    outcome.is_some_and(|outcome| matches!(outcome.status, RegressionGateStatus::Rejected))
        && !gate.accept_rejected
}

fn rejected_gate_row(cve: &str, outcome: Option<&RegressionGateOutcome>) -> Value {
    json!({
        "cve": cve,
        "status": "rejected-by-gate",
        "reason": outcome.map(|o| o.reason.clone()),
        "preFixHits": outcome.and_then(|o| o.pre_fix_hits),
        "postFixHits": outcome.and_then(|o| o.post_fix_hits),
    })
}

fn harvested_entry_row(
    cve: &str,
    entry: &HarvestedCatalogEntry,
    gate_outcome: Option<RegressionGateOutcome>,
) -> Value {
    json!({
        "cve": cve,
        "status": "harvested",
        "entryId": entry.id,
        "hunt": entry.hunt.as_str(),
        "cwe": entry.cwe,
        "gate": gate_outcome,
    })
}

fn gate_outcome_or_unverified(
    target: &Path,
    cve: &str,
    record: &Value,
    pattern: &Value,
) -> RegressionGateOutcome {
    match run_regression_gate(target, cve, record, pattern) {
        Ok(outcome) => outcome,
        Err(err) => {
            RegressionGateOutcome::unverified(format!("regression-gate error for {cve}: {err:#}"))
        }
    }
}

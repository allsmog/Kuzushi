use serde_json::{json, Value};
use std::path::{Path, PathBuf};

#[derive(Default)]
pub(super) struct HarvestStats {
    pub(super) harvested: u32,
    pub(super) skipped: u32,
    pub(super) failed: u32,
    pub(super) deferred: u32,
    pub(super) rejected_by_gate: u32,
    pub(super) validated_by_gate: u32,
    pub(super) unverified_by_gate: u32,
}

pub(super) struct HarvestGateConfig {
    pub(super) enabled: bool,
    pub(super) accept_rejected: bool,
    pub(super) target: Option<PathBuf>,
}

pub(super) fn harvest_result(
    output_path: &Path,
    per_cve: Vec<Value>,
    total_cves: usize,
    stats: &HarvestStats,
    gate: &HarvestGateConfig,
) -> Value {
    let summary = format!(
        "Unaccepted catalog draft: {} entr{}; {} failed, {} skipped, {} deferred. Source claims require review.",
        stats.harvested,
        entry_suffix(stats.harvested),
        stats.failed, stats.skipped, stats.deferred,
    );
    let data = json!({
        "outputPath": output_path.display().to_string(),
        "perCve": per_cve,
        "summary": harvest_summary(total_cves, stats, gate),
        "draft": true,
        "accepted": false,
        "patternsVerified": false,
        "coverage": {"complete":false},
    });
    let mut result = crate::module_result::partial_output_result(
        summary.clone(),
        summary,
        vec![
            json!({"code":"unaccepted-catalog","message":"Catalog patterns and advisory/source claims remain unaccepted. Review per-advisory outcomes and omissions before reusing them; this action does not establish repository coverage or start hunts."}),
        ],
        data,
    );
    result["artifacts"] = json!([{
        "label": "catalog",
        "path": output_path.display().to_string(),
    }]);
    result
}

fn harvest_summary(total_cves: usize, stats: &HarvestStats, gate: &HarvestGateConfig) -> Value {
    json!({
        "totalCves": total_cves,
        "harvested": stats.harvested,
        "skipped": stats.skipped,
        "failed": stats.failed,
        "deferred": stats.deferred,
        "regressionGate": {
            "enabled": gate.enabled,
            "acceptRejected": gate.accept_rejected,
            "validated": stats.validated_by_gate,
            "unverified": stats.unverified_by_gate,
            "rejected": stats.rejected_by_gate,
        },
    })
}

fn entry_suffix(count: u32) -> &'static str {
    if count == 1 {
        "y"
    } else {
        "ies"
    }
}

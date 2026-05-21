use serde_json::{json, Value};
use std::path::{Path, PathBuf};

#[derive(Default)]
pub(super) struct HarvestStats {
    pub(super) harvested: u32,
    pub(super) skipped: u32,
    pub(super) failed: u32,
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
        "threat-intel:harvest wrote {} catalog entr{} to {}",
        stats.harvested,
        entry_suffix(stats.harvested),
        output_path.display()
    );
    let data = json!({
        "outputPath": output_path.display().to_string(),
        "perCve": per_cve,
        "summary": harvest_summary(total_cves, stats, gate),
    });
    let mut result = crate::module_result::completed_output_result(summary.clone(), summary, data);
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
    if count == 1 { "y" } else { "ies" }
}

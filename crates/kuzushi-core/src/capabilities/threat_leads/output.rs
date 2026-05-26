use serde_json::{json, Value};
use std::path::Path;

pub(super) fn tool_output(target: &Path, report: Value) -> Value {
    let count = report["leadCount"].as_u64().unwrap_or_default();
    let artifact = super::threat_leads_artifact_path(target);
    let summary = super::threat_leads_summary_path(target);
    let output = format!(
        "threat-leads: {} lead{} for {}\n  Artifact: {}",
        count,
        if count == 1 { "" } else { "s" },
        target.display(),
        artifact.display()
    );
    let mut result = crate::module_result::completed_output_result(output.clone(), output, report);
    result["artifacts"] = json!([
        {"label": "threat-leads", "path": artifact.display().to_string()},
        {"label": "threat-leads-summary", "path": summary.display().to_string()},
    ]);
    result
}

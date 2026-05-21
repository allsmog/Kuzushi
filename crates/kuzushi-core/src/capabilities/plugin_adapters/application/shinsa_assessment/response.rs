use super::*;

pub(super) fn shinsa_response(
    tool_name: &str,
    target: &Path,
    mode: &str,
    plugin_root: &Path,
    output_dir: &str,
    artifacts: artifacts::ShinsaArtifacts,
    findings: Vec<Finding>,
    persisted: Option<GenericPersistedRun>,
) -> Value {
    let output = format!(
        "{tool_name} complete\n  Mode:     {mode}\n  Output:   {}/\n  Artifacts: shinsa-state.json compliance-report.md\n  Findings: {}",
        output_dir,
        findings.len()
    );
    let mut result = crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "target": target.display().to_string(),
            "mode": mode,
            "pluginRoot": plugin_root.display().to_string(),
            "outputDir": output_dir,
            "statePath": artifacts.state_path.display().to_string(),
            "reportPath": artifacts.report_path.display().to_string(),
            "findings": findings,
            "persisted": persisted,
        }),
    );
    result["artifacts"] = json!([
        { "label": "state", "path": artifacts.state_path.display().to_string() },
        { "label": "report", "path": artifacts.report_path.display().to_string() },
    ]);
    result["costUsd"] = json!(0.0);
    result
}

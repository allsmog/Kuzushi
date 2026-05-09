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
    json!({
        "ok": true,
        "output": format!(
            "{tool_name} complete\n  Mode:     {mode}\n  Output:   {}/\n  Artifacts: shinsa-state.json compliance-report.md\n  Findings: {}",
            output_dir,
            findings.len()
        ),
        "data": {
            "target": target.display().to_string(),
            "mode": mode,
            "pluginRoot": plugin_root.display().to_string(),
            "outputDir": output_dir,
            "statePath": artifacts.state_path.display().to_string(),
            "reportPath": artifacts.report_path.display().to_string(),
            "findings": findings,
            "persisted": persisted,
        },
        "costUsd": 0.0,
    })
}

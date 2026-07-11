use crate::capabilities::uaf_hunt::domain::UafHuntReport;
use serde_json::{json, Value};

pub fn report_to_tool_json(report: &UafHuntReport) -> Value {
    let summary = format!(
        "uaf-hunt: {} finding{} under {}{}",
        report.count,
        if report.count == 1 { "" } else { "s" },
        report.target,
        if report.truncated { " (step cap reached)" } else { "" }
    );
    let warnings = incomplete_warnings(report);
    let mut result = if warnings.is_empty() {
        crate::module_result::completed_output_result(summary.clone(), summary, json!(report))
    } else {
        crate::module_result::partial_output_result(
            summary.clone(),
            summary,
            warnings,
            json!(report),
        )
    };
    result["costUsd"] = json!(report.cost_usd);
    if let Some(artifact) = transcript_artifact(report) {
        result["artifacts"] = json!([artifact]);
    }
    result
}

fn incomplete_warnings(report: &UafHuntReport) -> Vec<Value> {
    let mut warnings = Vec::new();
    if report.truncated {
        warnings.push(json!(
            "agent reached the step cap before returning a findings envelope; zero findings is not a clean verdict"
        ));
    }
    if let Some(error) = report.first_clang_error.as_ref() {
        warnings.push(json!(format!("clang navigation was incomplete: {error}")));
    }
    warnings
}

fn transcript_artifact(report: &UafHuntReport) -> Option<Value> {
    let path = report.persisted.as_ref()?.transcript_path.as_ref()?;
    Some(json!({
        "label": "transcript",
        "path": path,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_uses_completed_envelope_and_transcript_artifact() {
        let report = UafHuntReport {
            target: "/repo".to_string(),
            count: 0,
            findings: Vec::new(),
            persisted: Some(crate::capabilities::uaf_hunt::domain::UafHuntPersistedRun {
                run_id: "run-1".to_string(),
                findings_db: "/repo/.kuzushi/findings.db".to_string(),
                transcript_path: Some("/repo/.kuzushi/uaf-hunt-runs/run-1/transcript.jsonl".to_string()),
            }),
            compile_commands_path: "/repo/compile_commands.json".to_string(),
            clang_tool_calls: 2,
            first_clang_error: None,
            steps_used: 4,
            truncated: false,
            cost_usd: 0.03,
        };

        let output = report_to_tool_json(&report);

        assert_eq!(output["ok"], json!(true));
        assert_eq!(output["status"], json!("completed"));
        assert_eq!(output["summary"], json!("uaf-hunt: 0 findings under /repo"));
        assert_eq!(output["costUsd"], json!(0.03));
        assert!(output["artifacts"][0]["path"]
            .as_str()
            .is_some_and(|path| path.ends_with("transcript.jsonl")));
    }

    #[test]
    fn truncated_or_degraded_hunt_is_partial_not_clean() {
        let report = UafHuntReport {
            target: "/repo".to_string(),
            count: 0,
            findings: Vec::new(),
            persisted: None,
            compile_commands_path: "/repo/compile_commands.json".to_string(),
            clang_tool_calls: 1,
            first_clang_error: Some("index unavailable".to_string()),
            steps_used: 4,
            truncated: true,
            cost_usd: 0.03,
        };

        let output = report_to_tool_json(&report);

        assert_eq!(output["status"], json!("partial"));
        assert_eq!(output["ok"], json!(true));
        assert_eq!(output["warnings"].as_array().unwrap().len(), 2);
        assert!(output["summary"].as_str().unwrap().contains("step cap"));
    }
}

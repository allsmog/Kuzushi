use crate::capabilities::uaf_hunt::domain::UafHuntReport;
use serde_json::{json, Value};

pub fn report_to_tool_json(report: &UafHuntReport) -> Value {
    let summary = format!(
        "UAF source analysis: {} candidate{}{}",
        report.count,
        if report.count == 1 { "" } else { "s" },
        if report.is_partial() {
            "; partial local analysis"
        } else {
            ""
        }
    );
    let warnings = incomplete_warnings(report);
    let text = output_text(report, &summary);
    let mut result = if warnings.is_empty() {
        crate::module_result::completed_output_result(summary.clone(), text, json!(report))
    } else {
        crate::module_result::partial_output_result(summary.clone(), text, warnings, json!(report))
    };
    result["data"]["localIoLimits"] = super::local_limits::receipt();
    append_compiler_input(&mut result, report);
    let observed = crate::runtime::RuntimeCost::from_usd(report.cost_usd, "UAF hunt cost")
        .expect("agent loop validates cost before report construction");
    let cost = if report.cost_usd_exact {
        crate::runtime::RuntimeCostReport::known(observed)
    } else {
        crate::runtime::RuntimeCostReport::incomplete(observed)
    };
    crate::module_result::apply_runtime_cost_report(&mut result, cost);
    if let Some(artifact) = transcript_artifact(report) {
        result["artifacts"] = json!([artifact]);
    }
    result
}

fn output_text(report: &UafHuntReport, summary: &str) -> String {
    let mut rows = vec![
        summary.to_owned(),
        "Unverified source-analysis candidates. Review evidence before deciding.".into(),
        format!(
            "Navigation calls: {}. Repository tool calls: {}.",
            report.clang_tool_calls, report.repo_tool_calls
        ),
        format!(
            "Model steps: {} used / {} maximum. Navigation deadline: {}s.",
            report.steps_used, report.max_agent_steps, report.clang_timeout_secs
        ),
        "Repository search stops after 5 seconds. Local replies above 512 KiB are refused.".into(),
        "Scope: whole-repository analysis. Accepted discovery scopes are unsupported.".into(),
        "Complete repository coverage is not established. Full receipt includes technical limits."
            .into(),
    ];
    if let Some(database) = &report.compile_database {
        rows.insert(
            2,
            format!(
                "Compiler commands: {}; frozen before navigation.",
                database.entries
            ),
        );
    }
    rows.join("\n")
}

fn append_compiler_input(result: &mut Value, report: &UafHuntReport) {
    let Some(database) = &report.compile_database else {
        return;
    };
    result["data"]["inputDocument"] = json!({"schemaVersion":1,"text":format!(
        "FROZEN COMPILER CONFIGURATION\nOriginal file: {}\nSource SHA-256: {}\nPrepared SHA-256: {}\nSource bytes: {}\nPrepared bytes: {}\nCommands: {}\n\nCaptured before navigation. Relative working directories use the original file's directory.\nThe helper receives a private copy. Repository configuration and compiler-driver probing are disabled for this selection.\nThis receipt omits command contents and the model prompt. Reading starts no work.",
        database.source_path.display(), database.source_sha256, database.prepared_sha256,
        database.source_bytes, database.prepared_bytes, database.entries
    )});
}

fn incomplete_warnings(report: &UafHuntReport) -> Vec<Value> {
    let mut warnings = navigation_warnings(report);
    if report.truncated {
        warnings.push(json!("agent reached the step cap before returning a findings envelope; zero findings is not a clean verdict"));
    }
    warnings
}

fn navigation_warnings(report: &UafHuntReport) -> Vec<Value> {
    let mut warnings = Vec::new();
    if let Some(error) = report.first_clang_error.as_ref() {
        warnings.push(json!(format!("clang navigation was incomplete: {error}")));
    }
    if let Some(error) = report.first_repo_error.as_ref() {
        warnings.push(json!(format!(
            "repository navigation was incomplete: {error}"
        )));
    }
    if report.clang_tool_calls == 0 {
        warnings.push(json!(
            "No clang navigation was recorded. Empty findings do not establish coverage."
        ));
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

    fn complete_report() -> UafHuntReport {
        UafHuntReport {
            target: "/repo".to_string(),
            count: 0,
            findings: Vec::new(),
            persisted: Some(crate::capabilities::uaf_hunt::domain::UafHuntPersistedRun {
                run_id: "run-1".to_string(),
                findings_db: "/repo/.kuzushi/findings.db".to_string(),
                transcript_path: Some(
                    "/repo/.kuzushi/uaf-hunt-runs/run-1/transcript.jsonl".to_string(),
                ),
            }),
            compile_commands_path: "/repo/compile_commands.json".to_string(),
            compile_database: None,
            clang_tool_calls: 2,
            first_clang_error: None,
            repo_tool_calls: 0,
            first_repo_error: None,
            max_agent_steps: 120,
            clang_timeout_secs: 60,
            steps_used: 4,
            truncated: false,
            cost_usd: 0.03,
            cost_usd_exact: true,
        }
    }

    #[test]
    fn output_uses_completed_envelope_and_transcript_artifact() {
        let report = complete_report();

        let output = report_to_tool_json(&report);

        assert_eq!(output["ok"], json!(true));
        assert_eq!(output["status"], json!("completed"));
        assert_eq!(
            output["summary"],
            json!("UAF source analysis: 0 candidates")
        );
        assert_eq!(output["costUsd"], json!(0.03));
        assert!(output["artifacts"][0]["path"]
            .as_str()
            .is_some_and(|path| path.ends_with("transcript.jsonl")));
    }

    #[test]
    fn truncated_or_degraded_hunt_is_partial_not_clean() {
        let mut report = complete_report();
        report.persisted = None;
        report.clang_tool_calls = 1;
        report.first_clang_error = Some("index unavailable".into());
        report.truncated = true;

        let output = report_to_tool_json(&report);

        assert_eq!(output["status"], json!("partial"));
        assert_eq!(output["ok"], json!(true));
        assert_eq!(output["warnings"].as_array().unwrap().len(), 2);
        assert!(output["summary"]
            .as_str()
            .unwrap()
            .contains("partial local analysis"));
    }
    #[test]
    fn missing_navigation_and_repository_errors_cannot_look_clean() {
        let mut report = complete_report();
        report.clang_tool_calls = 0;
        assert_eq!(report_to_tool_json(&report)["status"], "partial");
        report.clang_tool_calls = 1;
        report.repo_tool_calls = 1;
        report.first_repo_error = Some("owned search failed".into());
        let result = report_to_tool_json(&report);
        assert_eq!(result["status"], "partial");
        assert!(result["warnings"][0]
            .as_str()
            .unwrap()
            .contains("owned search failed"));
        assert_eq!(result["data"]["repoToolCalls"], 1);
    }

    #[test]
    fn unknown_cost_stays_unknown_in_the_envelope_and_payload() {
        let mut report = complete_report();
        report.cost_usd = 0.0;
        report.cost_usd_exact = false;
        let result = report_to_tool_json(&report);
        for value in [&result, &result["data"]] {
            assert_eq!(value["costUsd"], Value::Null);
            assert_eq!(value["providerSpendUnresolved"], true);
        }
    }

    #[test]
    fn historical_reports_default_new_local_receipt_fields() {
        let mut value = json!(complete_report());
        for field in [
            "repoToolCalls",
            "firstRepoError",
            "maxAgentSteps",
            "clangTimeoutSecs",
        ] {
            value.as_object_mut().unwrap().remove(field);
        }
        let report: UafHuntReport = serde_json::from_value(value).unwrap();
        assert_eq!(report.repo_tool_calls, 0);
        assert_eq!(report.clang_timeout_secs, 0);
        assert!(report.first_repo_error.is_none());
        assert!(report.compile_database.is_none());
    }

    #[test]
    fn compiler_receipt_is_readable_without_claiming_to_be_the_model_prompt() {
        let mut report = complete_report();
        report.compile_database = Some(
            kuzushi_mcp_common::compile_database::CompileDatabaseReceipt {
                source_path: "/owned-build/chosen.json".into(),
                source_sha256: "1".repeat(64),
                source_bytes: 98,
                prepared_sha256: "2".repeat(64),
                prepared_bytes: 120,
                entries: 1,
            },
        );
        let result = report_to_tool_json(&report);
        assert_eq!(result["data"]["compileDatabase"]["entries"], 1);
        let text = result["data"]["inputDocument"]["text"].as_str().unwrap();
        assert!(text.contains("FROZEN COMPILER CONFIGURATION"));
        assert!(text.contains("/owned-build/chosen.json"));
        assert!(text.contains("receipt omits command contents and the model prompt"));
        assert!(!result["output"].as_str().unwrap().contains("/owned-build"));
    }
}

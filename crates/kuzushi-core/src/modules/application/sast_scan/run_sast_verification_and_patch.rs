use super::*;
use crate::{Finding, Severity};

pub(in crate::modules) fn run_sast_verification_and_patch(
    registry: &ModuleRegistry,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    option_store: &crate::options::ToolOptionStore,
    store: &crate::findings::FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
    requests: &SastScanRequests,
) -> Result<(Vec<Value>, Vec<Value>)> {
    let mut verification_results = Vec::new();
    let mut patch_results = Vec::new();
    for fingerprint in selected_verification_fingerprints(store, run_ids, requests)? {
        let result = run_sast_verification_for_fingerprint(
            registry,
            input,
            ctx,
            runtime,
            option_store,
            artifacts,
            requests,
            fingerprint,
        )?;
        verification_results.push(result.verification);
        patch_results.extend(result.patch);
    }
    Ok((verification_results, patch_results))
}

fn selected_verification_fingerprints(
    store: &crate::findings::FindingStore,
    run_ids: &SastRunIds,
    requests: &SastScanRequests,
) -> Result<Vec<String>> {
    let mut findings = true_positive_findings_for_sast_runs(store, run_ids)?
        .into_iter()
        .filter(|finding| requests.verify_when.matches(finding))
        .filter(|finding| finding_has_votes(finding, requests.verify_votes))
        .collect::<Vec<_>>();
    findings.sort_by_key(|finding| {
        (
            std::cmp::Reverse(severity_rank(finding.severity)),
            finding.file_path.clone(),
            finding.start_line,
            finding.fingerprint.clone(),
        )
    });
    if let Some(max) = requests.verify_max {
        findings.truncate(max);
    }
    Ok(findings
        .into_iter()
        .map(|finding| finding.fingerprint)
        .collect())
}

fn finding_has_votes(finding: &Finding, verify_votes: Option<usize>) -> bool {
    let Some(required) = verify_votes else {
        return true;
    };
    finding.corroboration_count.max(1) as usize >= required
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
        Severity::Unknown => 0,
    }
}

struct SastVerificationResult {
    verification: Value,
    patch: Option<Value>,
}

fn run_sast_verification_for_fingerprint(
    registry: &ModuleRegistry,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    option_store: &crate::options::ToolOptionStore,
    artifacts: &SastRunArtifacts,
    requests: &SastScanRequests,
    fingerprint: String,
) -> Result<SastVerificationResult> {
    let verification = run_sast_verifier(
        registry,
        input,
        ctx,
        runtime,
        option_store,
        fingerprint.clone(),
    )?;
    write_verify_jsonl(artifacts, &verification)?;
    let patch = run_optional_sast_patch(
        registry,
        input,
        ctx,
        runtime,
        option_store,
        artifacts,
        requests,
        &fingerprint,
        &verification,
    )?;
    Ok(SastVerificationResult {
        verification,
        patch,
    })
}

fn run_sast_verifier(
    registry: &ModuleRegistry,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    option_store: &crate::options::ToolOptionStore,
    fingerprint: String,
) -> Result<Value> {
    let verify_input = with_sast_prompt_override(
        json!({ "fingerprint": fingerprint }),
        input,
        ctx,
        "verify",
        "VERIFY_PROMPT",
    )?;
    run_sast_subtool(
        registry,
        "verify:finding",
        verify_input,
        ctx,
        runtime,
        option_store,
    )
}

fn run_optional_sast_patch(
    registry: &ModuleRegistry,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    option_store: &crate::options::ToolOptionStore,
    artifacts: &SastRunArtifacts,
    requests: &SastScanRequests,
    fingerprint: &str,
    verification: &Value,
) -> Result<Option<Value>> {
    if !requests.auto_patch || !sast_verification_exploitable(verification) {
        return Ok(None);
    }
    let patch = run_sast_subtool(
        registry,
        "patch:finding",
        sast_patch_input(input, fingerprint),
        ctx,
        runtime,
        option_store,
    )?;
    write_patch_jsonl(artifacts, fingerprint, &patch)?;
    Ok(Some(patch))
}

fn sast_verification_exploitable(verification: &Value) -> bool {
    verification
        .pointer("/data/exploitable")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

pub(in crate::modules) fn sast_output_lines(
    primary_run_id: &str,
    findings_count: usize,
    workspace: &crate::workspace::WorkspaceTarget,
    reports: &SastPipelineReports,
    whitebox_enabled: bool,
    whitebox_artifacts: &WhiteboxArtifacts,
    post_processing: &SastPostProcessing,
    requests: &SastScanRequests,
) -> Vec<String> {
    let mut lines = vec![format!(
        "sast:scan {} completed: {} finding(s), db {}",
        primary_run_id,
        findings_count,
        workspace.findings_db_path().display()
    )];
    if whitebox_enabled {
        whitebox_artifacts.append_output_lines(&mut lines);
    }
    lines.push(format!("  Engines: {}", reports.engine_ids.join(", ")));
    append_triage_output_line(&mut lines, post_processing.triage.as_ref());
    if requests.needs_verification() {
        lines.push(format!(
            "      verified={} patched={}",
            post_processing.verification_results.len(),
            post_processing.patch_results.len()
        ));
    }
    lines
}

pub(in crate::modules) fn append_triage_output_line(
    lines: &mut Vec<String>,
    triage: Option<&Value>,
) {
    if let Some(triage_output) = triage
        .and_then(|value| value.get("output"))
        .and_then(Value::as_str)
    {
        lines.push(triage_output.to_string());
    }
}

pub(in crate::modules) fn whitebox_mode_label(
    whitebox_static: Option<&WhiteboxStaticPolicy>,
) -> &str {
    whitebox_static.map_or("standard", |policy| policy.mode.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TriageOutcome, TriageVerdict};
    use std::path::Path;

    #[test]
    fn selected_verification_fingerprints_filters_votes_when_and_max() {
        let store = FindingStore::open_in_memory().unwrap();
        let run_ids = SastRunIds {
            primary: "run-select".to_string(),
            native: None,
            agentic: None,
            carlini: None,
            taint_iris: None,
            taint_iris_next: None,
            systems_hunt: None,
        };
        store
            .insert_scan_run(&run_ids.primary, Path::new("/tmp/repo"), "completed")
            .unwrap();

        let high = seed_verification_selection_findings(&store, &run_ids.primary);
        let requests = SastScanRequests::from_input(&json!({
            "verify": true,
            "verifyWhen": "severity>=high",
            "verifyVotes": 2,
            "verifyMax": 1
        }))
        .unwrap();

        let selected = selected_verification_fingerprints(&store, &run_ids, &requests).unwrap();

        assert_eq!(selected, vec![high.fingerprint]);
    }

    fn seed_verification_selection_findings(store: &FindingStore, run_id: &str) -> Finding {
        let high = insert_true_positive(
            store,
            run_id,
            test_finding("semgrep", "rule/cwe-89", "src/db.rs", 10, Severity::High),
        );
        store
            .insert_finding(
                run_id,
                &test_finding(
                    "systems-hunt",
                    "systems/cwe-89",
                    "src/db.rs",
                    11,
                    Severity::High,
                ),
            )
            .unwrap();
        insert_true_positive(
            store,
            run_id,
            test_finding("semgrep", "rule/cwe-78", "src/cmd.rs", 50, Severity::Critical),
        );
        insert_true_positive(
            store,
            run_id,
            test_finding("semgrep", "rule/cwe-79", "src/view.rs", 30, Severity::Medium),
        );
        high
    }

    fn test_finding(
        tool: &str,
        rule_id: &str,
        file_path: &str,
        line: u32,
        severity: Severity,
    ) -> Finding {
        Finding::new_tool(tool, rule_id, file_path, line, None, severity, rule_id)
    }

    fn insert_true_positive(store: &FindingStore, run_id: &str, finding: Finding) -> Finding {
        let id = store.insert_finding(run_id, &finding).unwrap();
        store
            .save_triage(
                id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.90,
                    rationale: "test true positive".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
        finding
    }
}

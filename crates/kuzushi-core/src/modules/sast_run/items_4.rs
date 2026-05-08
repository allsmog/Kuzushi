use super::prelude::*;
use super::*;

pub(in crate::modules) fn write_whitebox_diff_scope_json(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
    diff_base: &str,
) -> Result<Value> {
    let current_findings = findings_for_sast_runs(store, run_ids)?;
    let previous_findings = store.list_findings(FindingListFilter::MAX_LIMIT)?;
    let artifact_path = artifacts.dir.join("whitebox-diff-scope.json");
    let mut report = serde_json::to_value(build_whitebox_diff_scope_report(
        workspace.root(),
        diff_base,
        &current_findings,
        &previous_findings,
    )?)?;
    if let Value::Object(object) = &mut report {
        object.insert(
            "artifact".to_string(),
            json!(artifact_path.display().to_string()),
        );
        object.insert(
            "policy".to_string(),
            json!("whitebox-static PR mode uses only local git diff data; no remote git provider is required"),
        );
    }
    fs::write(
        &artifact_path,
        format!("{}\n", serde_json::to_string_pretty(&report)?),
    )
    .with_context(|| format!("Could not write {}", artifact_path.display()))?;
    Ok(report)
}

pub(in crate::modules) fn true_positive_fingerprints_for_sast_runs(
    store: &FindingStore,
    run_ids: &SastRunIds,
) -> Result<Vec<String>> {
    let mut fingerprints = Vec::new();
    let mut seen = BTreeSet::new();
    for run_id in run_ids.all() {
        for finding in store.list_findings_for_scan_id(run_id)? {
            if finding
                .triage
                .as_ref()
                .is_some_and(|triage| triage.verdict == TriageVerdict::TruePositive)
                && seen.insert(finding.fingerprint.clone())
            {
                fingerprints.push(finding.fingerprint);
            }
        }
    }
    Ok(fingerprints)
}

pub(in crate::modules) fn sast_patch_input(sast_input: &Value, fingerprint: &str) -> Value {
    let mut patch_input = Map::new();
    patch_input.insert("fingerprint".to_string(), json!(fingerprint));
    for key in ["maxIterations", "buildCmd", "testCmd"] {
        if let Some(value) = sast_input.get(key) {
            patch_input.insert(key.to_string(), value.clone());
        }
    }
    Value::Object(patch_input)
}

pub(in crate::modules) fn write_sast_summary(
    artifacts: &SastRunArtifacts,
    result: &Value,
) -> Result<()> {
    fs::write(
        &artifacts.summary,
        format!("{}\n", serde_json::to_string_pretty(result)?),
    )
    .with_context(|| format!("Could not write {}", artifacts.summary.display()))
}

pub(in crate::modules) fn write_triage_jsonl(
    artifacts: &SastRunArtifacts,
    triage_output: &Value,
) -> Result<()> {
    let results = triage_output
        .pointer("/data/results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if results.is_empty() {
        append_jsonl(
            &artifacts.triage_jsonl,
            json!({
                "type": "triage:complete",
                "data": triage_output.get("data").cloned().unwrap_or(Value::Null),
            }),
        )?;
        return Ok(());
    }

    for result in results {
        append_jsonl(
            &artifacts.triage_jsonl,
            json!({
                "type": "triage:complete",
                "fingerprint": result.get("fingerprint").cloned().unwrap_or(Value::Null),
                "data": result,
            }),
        )?;
    }
    Ok(())
}

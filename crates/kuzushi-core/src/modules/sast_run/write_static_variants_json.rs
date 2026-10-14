use super::*;

pub(in crate::modules) fn write_static_variants_json(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    run_ids: &SastRunIds,
    fold: IdentityFoldPolicy,
    artifacts: &SastRunArtifacts,
) -> Result<Value> {
    let findings = findings_for_sast_runs(store, run_ids, fold)?;
    let evidence_store = Some(StaticEvidenceStore::open(workspace)?);
    let variant_report =
        hunt_whitebox_static_variants(workspace.root(), &findings, evidence_store.as_ref(), 50)?;
    let artifact_path = artifacts.dir.join("static-variants.json");
    let report = json!({
        "count": variant_report.count,
        "patterns": variant_report.patterns,
        "variants": variant_report.variants,
        "artifact": artifact_path.display().to_string(),
        "deterministic": variant_report.deterministic,
        "policy": "whitebox-static variants are code-cited candidates only; no variant is statically_confirmed by inheritance",
    });
    artifacts.write_json("static-variants.json", "static variants", &report)?;
    Ok(report)
}

pub(in crate::modules) fn write_candidate_semgrep_rules_json(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    run_ids: &SastRunIds,
    fold: IdentityFoldPolicy,
    artifacts: &SastRunArtifacts,
) -> Result<Value> {
    let findings = findings_for_sast_runs(store, run_ids, fold)?;
    let evidence_store = Some(StaticEvidenceStore::open(workspace)?);
    let synthesis_report =
        synthesize_candidate_semgrep_rules(&findings, evidence_store.as_ref(), &[])?;
    let artifact_path = artifacts.dir.join("candidate-semgrep-rules.json");
    let report = json!({
        "count": synthesis_report.count,
        "validationPassed": synthesis_report.validation_passed,
        "candidates": synthesis_report.candidates,
        "artifact": artifact_path.display().to_string(),
        "deterministic": synthesis_report.deterministic,
        "policy": "candidate Semgrep rules are generated only from statically_confirmed findings and remain disabled until fixture validation passes and an operator enables them",
    });
    artifacts.write_json(
        "candidate-semgrep-rules.json",
        "candidate Semgrep rules",
        &report,
    )?;
    Ok(report)
}

pub(in crate::modules) fn write_whitebox_suppressions_json(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    run_ids: &SastRunIds,
    fold: IdentityFoldPolicy,
    artifacts: &SastRunArtifacts,
) -> Result<Value> {
    let findings = findings_for_sast_runs(store, run_ids, fold)?;
    let suppressions = load_whitebox_suppressions(workspace)?;
    let suppression_report =
        evaluate_whitebox_suppressions(workspace.root(), &findings, &suppressions, now_unix());
    let artifact_path = artifacts.dir.join("whitebox-suppressions.json");
    let report = json!({
        "totalSuppressions": suppression_report.total_suppressions,
        "activeSuppressions": suppression_report.active_suppressions,
        "suppressedCount": suppression_report.suppressed_count,
        "suppressedFindings": suppression_report.suppressed_findings,
        "staleCount": suppression_report.stale_suppressions.len(),
        "staleSuppressions": suppression_report.stale_suppressions,
        "expiredCount": suppression_report.expired_suppressions.len(),
        "expiredSuppressions": suppression_report.expired_suppressions,
        "findingsRemainVisible": suppression_report.findings_remain_visible,
        "auditNote": suppression_report.audit_note,
        "artifact": artifact_path.display().to_string(),
        "deterministic": true,
        "policy": "whitebox-static false-positive memory annotates suppressions only; suppressed findings remain in audit/report output",
    });
    artifacts.write_json(
        "whitebox-suppressions.json",
        "whitebox suppressions",
        &report,
    )?;
    Ok(report)
}

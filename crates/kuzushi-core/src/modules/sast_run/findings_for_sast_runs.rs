use super::*;

pub(in crate::modules) fn findings_for_sast_runs(
    store: &FindingStore,
    run_ids: &SastRunIds,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let mut seen = BTreeSet::new();
    for run_id in run_ids.all() {
        for finding in store.list_findings_for_scan_id(run_id)? {
            if seen.insert(finding.fingerprint.clone()) {
                findings.push(finding);
            }
        }
    }
    Ok(findings)
}

pub(in crate::modules) fn write_sast_scan_input(
    artifacts: &SastRunArtifacts,
    input: &Value,
) -> Result<()> {
    fs::write(
        &artifacts.scan_input,
        format!("{}\n", serde_json::to_string_pretty(input)?),
    )
    .with_context(|| format!("Could not write {}", artifacts.scan_input.display()))
}

pub(in crate::modules) fn write_static_ranking_json(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
) -> Result<Value> {
    let findings = findings_for_sast_runs(store, run_ids)?;
    let attack_surface = crate::attack_surface::build_attack_surface_map(workspace.root()).ok();
    let evidence_store = StaticEvidenceStore::open(workspace).ok();
    let threat_model = crate::load_persistent_threat_model(workspace.root());
    let ranked = rank_static_findings_with_threats(
        &findings,
        attack_surface.as_ref(),
        evidence_store.as_ref(),
        threat_model.as_ref(),
    )?;
    let artifact_path = artifacts.dir.join("static-ranking.json");
    let report = json!({
        "count": ranked.len(),
        "ranked": ranked,
        "attackSurfaceAvailable": attack_surface.is_some(),
        "threatModelAvailable": threat_model.is_some(),
        "evidenceDb": evidence_store
            .as_ref()
            .map(|store| store.db_path().to_string()),
        "artifact": artifact_path.display().to_string(),
        "deterministic": true,
        "factors": [
            "attackSurfaceReachability",
            "sourceSinkClass",
            "dataSensitivity",
            "privilegeBoundary",
            "sanitizerAbsence",
            "frameworkContext",
            "codeqlFlowQuality",
            "confidence",
            "threatModelPriority"
        ],
    });
    fs::write(
        &artifact_path,
        format!("{}\n", serde_json::to_string_pretty(&report)?),
    )
    .with_context(|| format!("Could not write {}", artifact_path.display()))?;
    Ok(report)
}

pub(in crate::modules) fn write_static_narratives_json(
    store: &FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
    static_ranking: Option<&Value>,
) -> Result<Value> {
    let findings = findings_for_sast_runs(store, run_ids)?;
    let ranked = static_ranking
        .and_then(|ranking| ranking.get("ranked").cloned())
        .map(serde_json::from_value::<Vec<StaticRankedFinding>>)
        .transpose()?
        .unwrap_or_default();
    let narrative_report = build_static_narrative_report(&findings, &ranked)?;
    let artifact_path = artifacts.dir.join("static-narratives.json");
    let report = json!({
        "count": narrative_report.count,
        "narratives": narrative_report.narratives,
        "artifact": artifact_path.display().to_string(),
        "deterministic": narrative_report.deterministic,
    });
    fs::write(
        &artifact_path,
        format!("{}\n", serde_json::to_string_pretty(&report)?),
    )
    .with_context(|| format!("Could not write {}", artifact_path.display()))?;
    Ok(report)
}

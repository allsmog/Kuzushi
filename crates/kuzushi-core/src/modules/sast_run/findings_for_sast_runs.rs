use super::*;
use std::path::Path;

pub(in crate::modules) fn findings_for_sast_runs(
    store: &FindingStore,
    run_ids: &SastRunIds,
) -> Result<Vec<Finding>> {
    store.list_distinct_findings_for_scan_ids(&run_ids.all())
}

/// Distinct findings next to the raw producer observations they fold, so a
/// run summary never presents a corroborated count as the observation count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::modules) struct SastFindingTally {
    pub distinct: usize,
    pub observations: usize,
}

impl SastFindingTally {
    pub(in crate::modules) fn for_runs(
        store: &FindingStore,
        run_ids: &SastRunIds,
        distinct: usize,
    ) -> Result<Self> {
        let observations = store.count_finding_observations_for_scan_ids(&run_ids.all())?;
        Ok(Self {
            distinct,
            observations,
        })
    }

    pub(in crate::modules) fn label(self) -> String {
        if self.observations > self.distinct {
            return format!(
                "{} distinct finding(s) from {} observation(s)",
                self.distinct, self.observations
            );
        }
        format!("{} finding(s)", self.distinct)
    }
}

pub(in crate::modules) fn write_sast_scan_input(
    workspace: &WorkspaceTarget,
    run_id: &str,
    artifacts: &SastRunArtifacts,
    input: &Value,
) -> Result<()> {
    let spec = crate::run_artifacts::scan_pipeline_artifact_spec(SAST_SCAN_INPUT_FILE)
        .context("scan input artifact must be declared")?;
    crate::run_artifacts::write_run_artifact_json(
        workspace.root(),
        run_id,
        SAST_SCAN_INPUT_FILE,
        spec.label,
        input,
    )
    .map(|_| ())
    .with_context(|| format!("Could not write {}", artifacts.scan_input.display()))
}

pub(in crate::modules) fn write_static_ranking_json(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
) -> Result<Value> {
    let findings = findings_for_sast_runs(store, run_ids)?;
    let mut enrichments = load_static_ranking_enrichments(workspace);
    let (ranked, evidence_warnings) = rank_static_findings_with_threats_degraded(
        &findings,
        enrichments.attack_surface.as_ref(),
        enrichments.evidence_store.as_ref(),
        enrichments.threat_model.as_ref(),
    )?;
    enrichments.warnings.extend(evidence_warnings);
    let artifact_path = artifacts.dir.join("static-ranking.json");
    let report = static_ranking_report(ranked, enrichments, &artifact_path);
    artifacts.write_json("static-ranking.json", "static ranking", &report)?;
    Ok(report)
}

struct StaticRankingEnrichments {
    attack_surface: Option<crate::attack_surface::AttackSurfaceMap>,
    evidence_store: Option<StaticEvidenceStore>,
    threat_model: Option<Value>,
    warnings: Vec<String>,
}

fn load_static_ranking_enrichments(workspace: &WorkspaceTarget) -> StaticRankingEnrichments {
    let mut warnings = Vec::new();
    let attack_surface = optional_enrichment(
        "attack surface",
        crate::attack_surface::build_attack_surface_map(workspace.root()),
        &mut warnings,
    );
    let evidence_store = optional_enrichment(
        "static evidence store",
        StaticEvidenceStore::open(workspace),
        &mut warnings,
    );
    let threat_model = optional_enrichment(
        "threat model",
        crate::try_load_persistent_threat_model(workspace.root()),
        &mut warnings,
    )
    .flatten();
    StaticRankingEnrichments {
        attack_surface,
        evidence_store,
        threat_model,
        warnings,
    }
}

fn static_ranking_report(
    ranked: Vec<StaticRankedFinding>,
    enrichments: StaticRankingEnrichments,
    artifact_path: &Path,
) -> Value {
    json!({
        "count": ranked.len(),
        "ranked": ranked,
        "attackSurfaceAvailable": enrichments.attack_surface.is_some(),
        "threatModelAvailable": enrichments.threat_model.is_some(),
        "evidenceDb": enrichments.evidence_store.as_ref()
            .map(|store| store.db_path().to_string()),
        "artifact": artifact_path.display().to_string(),
        "deterministic": true,
        "warnings": enrichments.warnings,
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
    })
}

fn optional_enrichment<T>(label: &str, result: Result<T>, warnings: &mut Vec<String>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            warnings.push(format!("{label} unavailable: {error:#}"));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tally_label_names_observations_only_when_corroboration_folded_them() {
        let equal = SastFindingTally {
            distinct: 3,
            observations: 3,
        };
        let folded = SastFindingTally {
            distinct: 67,
            observations: 130,
        };

        assert_eq!(equal.label(), "3 finding(s)");
        assert_eq!(
            folded.label(),
            "67 distinct finding(s) from 130 observation(s)"
        );
    }

    #[test]
    fn optional_enrichment_records_degraded_state_without_failing() {
        let mut warnings = Vec::new();
        let value = optional_enrichment::<usize>(
            "fixture",
            Err(anyhow::anyhow!("malformed optional artifact")),
            &mut warnings,
        );

        assert_eq!(value, None);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("malformed optional artifact"));
    }
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
    artifacts.write_json("static-narratives.json", "static narratives", &report)?;
    Ok(report)
}

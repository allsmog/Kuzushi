use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

use crate::diff_scope::build_whitebox_diff_scope_report;
use crate::findings::{Finding, FindingListFilter, FindingStore, TriageVerdict};
use crate::semgrep_rule_synthesis::synthesize_candidate_semgrep_rules;
use crate::static_evidence::StaticEvidenceStore;
use crate::static_narrative::build_static_narrative_report;
use crate::static_ranking::{rank_static_findings_with_threats, StaticRankedFinding};
use crate::variant_ndiff::hunt_whitebox_static_variants;
use crate::whitebox_suppressions::{evaluate_whitebox_suppressions, load_whitebox_suppressions};
use crate::workspace::WorkspaceTarget;

use super::support::now_unix;

#[derive(Debug, Clone)]
pub(super) struct SastRunIds {
    pub(super) primary: String,
    pub(super) native: Option<String>,
    pub(super) agentic: Option<String>,
    pub(super) carlini: Option<String>,
    pub(super) taint_iris: Option<String>,
    pub(super) taint_iris_next: Option<String>,
    pub(super) systems_hunt: Option<String>,
}

impl SastRunIds {
    fn all(&self) -> Vec<&str> {
        let mut ids = Vec::new();
        if let Some(native) = self.native.as_deref() {
            ids.push(native);
        }
        if let Some(agentic) = self.agentic.as_deref() {
            ids.push(agentic);
        }
        if let Some(carlini) = self.carlini.as_deref() {
            ids.push(carlini);
        }
        if let Some(taint_iris) = self.taint_iris.as_deref() {
            ids.push(taint_iris);
        }
        if let Some(taint_iris_next) = self.taint_iris_next.as_deref() {
            ids.push(taint_iris_next);
        }
        if let Some(systems_hunt) = self.systems_hunt.as_deref() {
            ids.push(systems_hunt);
        }
        if ids.is_empty() {
            ids.push(&self.primary);
        }
        ids
    }
}

#[derive(Debug, Clone)]
pub(super) struct SastRunArtifacts {
    pub(super) dir: PathBuf,
    pub(super) summary: PathBuf,
    pub(super) triage_jsonl: PathBuf,
    pub(super) verify_jsonl: PathBuf,
}

impl SastRunArtifacts {
    pub(super) fn create(workspace: &WorkspaceTarget, run_id: &str) -> Result<Self> {
        let dir = workspace.root().join(".kuzushi").join("runs").join(run_id);
        fs::create_dir_all(&dir).with_context(|| format!("Could not create {}", dir.display()))?;
        let triage_jsonl = dir.join("triage.jsonl");
        let verify_jsonl = dir.join("verify.jsonl");
        fs::write(&triage_jsonl, "")
            .with_context(|| format!("Could not write {}", triage_jsonl.display()))?;
        fs::write(&verify_jsonl, "")
            .with_context(|| format!("Could not write {}", verify_jsonl.display()))?;
        Ok(Self {
            summary: dir.join("summary.json"),
            triage_jsonl,
            verify_jsonl,
            dir,
        })
    }
}

pub(super) fn fingerprints_for_sast_runs(
    store: &FindingStore,
    run_ids: &SastRunIds,
) -> Result<Vec<String>> {
    let mut fingerprints = Vec::new();
    let mut seen = BTreeSet::new();
    for run_id in run_ids.all() {
        for finding in store.list_findings_for_scan_id(run_id)? {
            if seen.insert(finding.fingerprint.clone()) {
                fingerprints.push(finding.fingerprint);
            }
        }
    }
    Ok(fingerprints)
}

fn findings_for_sast_runs(store: &FindingStore, run_ids: &SastRunIds) -> Result<Vec<Finding>> {
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

pub(super) fn write_sast_scan_input(artifacts: &SastRunArtifacts, input: &Value) -> Result<()> {
    let path = artifacts.dir.join("scan-input.json");
    fs::write(&path, format!("{}\n", serde_json::to_string_pretty(input)?))
        .with_context(|| format!("Could not write {}", path.display()))
}

pub(super) fn write_static_ranking_json(
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

pub(super) fn write_static_narratives_json(
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

pub(super) fn write_static_variants_json(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
) -> Result<Value> {
    let findings = findings_for_sast_runs(store, run_ids)?;
    let evidence_store = StaticEvidenceStore::open(workspace).ok();
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
    fs::write(
        &artifact_path,
        format!("{}\n", serde_json::to_string_pretty(&report)?),
    )
    .with_context(|| format!("Could not write {}", artifact_path.display()))?;
    Ok(report)
}

pub(super) fn write_candidate_semgrep_rules_json(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
) -> Result<Value> {
    let findings = findings_for_sast_runs(store, run_ids)?;
    let evidence_store = StaticEvidenceStore::open(workspace).ok();
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
    fs::write(
        &artifact_path,
        format!("{}\n", serde_json::to_string_pretty(&report)?),
    )
    .with_context(|| format!("Could not write {}", artifact_path.display()))?;
    Ok(report)
}

pub(super) fn write_whitebox_suppressions_json(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
) -> Result<Value> {
    let findings = findings_for_sast_runs(store, run_ids)?;
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
    fs::write(
        &artifact_path,
        format!("{}\n", serde_json::to_string_pretty(&report)?),
    )
    .with_context(|| format!("Could not write {}", artifact_path.display()))?;
    Ok(report)
}

pub(super) fn write_whitebox_diff_scope_json(
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

pub(super) fn true_positive_fingerprints_for_sast_runs(
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

pub(super) fn sast_patch_input(sast_input: &Value, fingerprint: &str) -> Value {
    let mut patch_input = Map::new();
    patch_input.insert("fingerprint".to_string(), json!(fingerprint));
    for key in ["maxIterations", "buildCmd", "testCmd"] {
        if let Some(value) = sast_input.get(key) {
            patch_input.insert(key.to_string(), value.clone());
        }
    }
    Value::Object(patch_input)
}

pub(super) fn write_sast_summary(artifacts: &SastRunArtifacts, result: &Value) -> Result<()> {
    fs::write(
        &artifacts.summary,
        format!("{}\n", serde_json::to_string_pretty(result)?),
    )
    .with_context(|| format!("Could not write {}", artifacts.summary.display()))
}

pub(super) fn write_triage_jsonl(
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

pub(super) fn write_verify_jsonl(
    artifacts: &SastRunArtifacts,
    verify_output: &Value,
) -> Result<()> {
    append_jsonl(
        &artifacts.verify_jsonl,
        json!({
            "type": "verification:complete",
            "fingerprint": verify_output.pointer("/data/fingerprint").cloned().unwrap_or(Value::Null),
            "data": verify_output.get("data").cloned().unwrap_or(Value::Null),
        }),
    )
}

pub(super) fn write_patch_jsonl(
    artifacts: &SastRunArtifacts,
    fingerprint: &str,
    patch_output: &Value,
) -> Result<()> {
    append_jsonl(
        &artifacts.verify_jsonl,
        json!({
            "type": "patch:complete",
            "fingerprint": fingerprint,
            "data": patch_output.get("data").cloned().unwrap_or(Value::Null),
        }),
    )
}

fn append_jsonl(path: &Path, value: Value) -> Result<()> {
    use std::io::Write;

    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("Could not open {}", path.display()))?;
    writeln!(file, "{}", serde_json::to_string(&value)?)
        .with_context(|| format!("Could not write {}", path.display()))
}

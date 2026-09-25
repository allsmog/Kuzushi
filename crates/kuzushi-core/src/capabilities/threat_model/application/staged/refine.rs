use super::super::*;
use super::gap_fill::run_gap_fill;
use super::question_closer::{open_question_texts, run_question_closer, QuestionCloserOutcome};
use crate::attack_surface::AttackSurface;
use crate::workspace::changed_files_since;
use std::time::Duration;

const MAX_REFINE_CHANGED_FILES: usize = 500;
const REFINE_GIT_TIMEOUT: Duration = Duration::from_secs(30);

/// Refine mode: a delta update of the persisted model. Deterministic where
/// possible — new corroborated findings attach as evidence rows on the
/// threats that cover their files (bumping likelihood at the ≥3 threshold),
/// and at most ONE LLM call covers entry points that appeared in files
/// changed since the recorded revision. A zero-delta refine costs $0 and
/// only refreshes provenance.
pub(crate) fn refine_threat_model(
    runtime: &dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
    verb: &str,
    input: BuildInput,
) -> Result<Value> {
    let (mut generated, source_bundle, delta) = load_refine_evidence(ctx, &input)?;
    emit_source_bundle_loaded(ctx, verb, source_bundle.loaded_count());
    emit_refine_delta(ctx, verb, &delta);
    let attach = attach_repository_evidence(&mut generated.document, &delta, &input);
    let (coverage, gap_method) =
        cover_changed_surfaces(runtime, ctx, verb, &input, &delta, &mut generated)?;
    let closer = close_open_questions(runtime, ctx, verb, &input, &delta, &mut generated)?;
    record_unmatched_findings(&mut generated.document, &attach.unmatched);
    let parked = park_unaccounted(&mut generated.document, &coverage.gaps);
    finalize_refined_document(
        &input,
        &mut generated.document,
        &delta,
        &attach,
        &coverage,
        gap_method,
        &closer,
        parked,
    )?;
    complete_refined_build(
        ctx,
        flavor,
        verb,
        input,
        generated,
        source_bundle,
        &coverage,
        parked,
    )
}

/// Attach the delta's new findings, reading each one's vulnerable line from
/// the workspace for its variant pattern.
fn attach_repository_evidence(
    document: &mut Value,
    delta: &RefineDelta,
    input: &BuildInput,
) -> EvidenceAttachment {
    attach_new_evidence(document, &delta.new_findings, &|finding| {
        finding_source_line(input.workspace_root(), finding)
    })
}

fn load_refine_state(
    ctx: &ToolExecutionContext<'_>,
    input: &BuildInput,
) -> Result<(GeneratedThreatModel, ThreatModelSourceBundle)> {
    let Some(selected) = load_selected_build_threat_model(input)? else {
        anyhow::bail!(
            "threat-model:build mode=refine requires a model for the selected scope and methodology; run a full build first"
        );
    };
    let source_bundle = load_threat_model_source_bundle(ctx, input)?;
    let generated = GeneratedThreatModel {
        document: normalize_document(selected.document, &input.methodology)?,
        bridge_findings: None,
        cost: crate::runtime::RuntimeCostReport::known(crate::runtime::RuntimeCost::ZERO),
    };
    Ok((generated, source_bundle))
}

fn load_refine_evidence(
    ctx: &ToolExecutionContext<'_>,
    input: &BuildInput,
) -> Result<(GeneratedThreatModel, ThreatModelSourceBundle, RefineDelta)> {
    let (generated, mut source_bundle) = load_refine_state(ctx, input)?;
    let mut delta = collect_refine_delta(input, ctx, &generated.document)?;
    source_bundle.authenticate_entry_point_sources(&delta.entry_point_catalog.receipt)?;
    delta.code_evidence = source_bundle.attach_source_code(
        input,
        &delta.grounding_surfaces,
        delta.entry_point_catalog.receipt.tree_hash.as_deref(),
        ctx,
    )?;
    delta
        .evidence_index
        .extend(delta.code_evidence.references.iter().cloned());
    Ok((generated, source_bundle, delta))
}

fn complete_refined_build(
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
    verb: &str,
    input: BuildInput,
    generated: GeneratedThreatModel,
    source_bundle: ThreatModelSourceBundle,
    coverage: &CoverageReport,
    parked: usize,
) -> Result<Value> {
    let reconciliation =
        BuildReconciliation::from_report(coverage, parked, "changed surfaces", &generated.document);
    complete_threat_model_build(
        ctx,
        flavor,
        verb,
        input,
        generated,
        source_bundle,
        reconciliation,
    )
}

pub(crate) struct RefineDelta {
    pub(crate) code_evidence: CodeEvidence,
    /// `None` = delta unknown (no recorded revision / not a git repo).
    pub(crate) changed_files: Option<Vec<String>>,
    pub(crate) new_findings: Vec<ConfirmedFindingRow>,
    pub(crate) changed_surfaces: Vec<AttackSurface>,
    pub(crate) grounding_surfaces: Vec<AttackSurface>,
    pub(crate) entry_point_catalog: crate::capabilities::entry_points::EntryPointCatalogGrounding,
    pub(crate) entry_point_catalog_changed: bool,
    /// Citable anchors for the question closer: surfaces, confirmed
    /// findings, and operator vuln ids known at refine time.
    pub(crate) evidence_index: BTreeSet<String>,
}

fn collect_refine_delta(
    input: &BuildInput,
    ctx: &ToolExecutionContext<'_>,
    document: &Value,
) -> Result<RefineDelta> {
    let changed_files = delta_changed_files(input, document)?;
    let grounding = load_prompt_grounding(input, ctx)?;
    let entry_point_catalog_changed =
        catalog_digest_changed(document, &grounding.entry_point_catalog);
    let mut evidence_index = super::research::build_evidence_index(&grounding, &[]);
    evidence_index.extend(input.vulns.iter().map(|row| row.id.clone()));
    let cited = existing_evidence_refs(document);
    let new_findings = grounding
        .confirmed_findings
        .into_iter()
        .filter(|finding| !cited.contains(&finding.fingerprint))
        .collect();
    let changed_surfaces = refine_changed_surfaces(
        grounding.surfaces.clone(),
        changed_files.as_deref(),
        entry_point_catalog_changed,
        &grounding.entry_point_catalog.catalog_ids,
    );
    Ok(RefineDelta {
        code_evidence: CodeEvidence::default(),
        changed_files,
        new_findings,
        changed_surfaces,
        grounding_surfaces: grounding.surfaces,
        entry_point_catalog: grounding.entry_point_catalog,
        entry_point_catalog_changed,
        evidence_index,
    })
}

fn catalog_digest_changed(
    document: &Value,
    current: &crate::capabilities::entry_points::EntryPointCatalogGrounding,
) -> bool {
    let Some(current_sha256) = current.receipt.sha256.as_deref() else {
        return false;
    };
    document
        .pointer("/provenance/entryPointCatalog/sha256")
        .and_then(Value::as_str)
        != Some(current_sha256)
}

fn delta_changed_files(input: &BuildInput, document: &Value) -> Result<Option<Vec<String>>> {
    let Some(revision) = document
        .pointer("/provenance/revision")
        .and_then(Value::as_str)
    else {
        return Ok(None);
    };
    changed_files_since(
        input.workspace_root(),
        revision,
        MAX_REFINE_CHANGED_FILES,
        REFINE_GIT_TIMEOUT,
    )
}

fn refine_changed_surfaces(
    surfaces: Vec<AttackSurface>,
    changed_files: Option<&[String]>,
    catalog_changed: bool,
    catalog_ids: &BTreeSet<String>,
) -> Vec<AttackSurface> {
    surfaces
        .into_iter()
        .filter(|surface| {
            changed_files.is_some_and(|changed| changed.contains(&surface.path))
                || (catalog_changed && catalog_ids.contains(&surface.id))
        })
        .collect()
}

fn existing_evidence_refs(document: &Value) -> BTreeSet<String> {
    let mut refs = BTreeSet::new();
    let Some(threats) = document.get("threats").and_then(Value::as_array) else {
        return refs;
    };
    for threat in threats {
        let Some(evidence) = threat.get("evidence").and_then(Value::as_array) else {
            continue;
        };
        for entry in evidence {
            if let Some(reference) = evidence_ref(entry) {
                refs.insert(reference);
            }
        }
    }
    refs
}

fn evidence_ref(entry: &Value) -> Option<String> {
    match entry {
        Value::String(reference) => Some(reference.trim().to_string()),
        Value::Object(fields) => fields
            .get("ref")
            .and_then(Value::as_str)
            .map(|reference| reference.trim().to_string()),
        _ => None,
    }
}

pub(crate) struct EvidenceAttachment {
    pub(crate) attached: usize,
    pub(crate) likelihood_raised: usize,
    /// Findings compacted onto their threat as a variant pattern.
    pub(crate) variant_patterns: usize,
    pub(crate) unmatched: Vec<ConfirmedFindingRow>,
}

/// Reads a finding's vulnerable line for its variant pattern; `None` when
/// the file is outside the workspace, unreadable, or shorter than the line.
pub(crate) type FindingLineReader<'a> = dyn Fn(&ConfirmedFindingRow) -> Option<String> + 'a;

/// The finding's own source line, read within the workspace and bounded.
fn finding_source_line(root: &std::path::Path, finding: &ConfirmedFindingRow) -> Option<String> {
    const MAX_SOURCE_BYTES: usize = 2 * 1024 * 1024;
    let text = crate::bounded_file::read_source_text_prefix_within(
        root,
        &root.join(&finding.file_path),
        MAX_SOURCE_BYTES,
    )
    .ok()??;
    let index = usize::try_from(finding.start_line.checked_sub(1)?).ok()?;
    text.lines().nth(index).map(str::to_string)
}

/// Deterministic evidence attach: a new finding lands on the first threat
/// whose affectedFiles / surface text covers its file, together with a
/// variant pattern built from its source line.
pub(crate) fn attach_new_evidence(
    document: &mut Value,
    new_findings: &[ConfirmedFindingRow],
    read_line: &FindingLineReader<'_>,
) -> EvidenceAttachment {
    let mut attachment = EvidenceAttachment {
        attached: 0,
        likelihood_raised: 0,
        variant_patterns: 0,
        unmatched: Vec::new(),
    };
    for finding in new_findings {
        if attach_finding(document, finding, read_line, &mut attachment) {
            attachment.attached += 1;
        } else {
            attachment.unmatched.push(clone_row(finding));
        }
    }
    attachment
}

fn clone_row(row: &ConfirmedFindingRow) -> ConfirmedFindingRow {
    ConfirmedFindingRow {
        fingerprint: row.fingerprint.clone(),
        title: row.title.clone(),
        file_path: row.file_path.clone(),
        start_line: row.start_line,
        severity: row.severity,
        cwe: row.cwe.clone(),
        evidence_snippet: row.evidence_snippet.clone(),
    }
}

fn attach_finding(
    document: &mut Value,
    finding: &ConfirmedFindingRow,
    read_line: &FindingLineReader<'_>,
    attachment: &mut EvidenceAttachment,
) -> bool {
    let Some(threats) = document.get_mut("threats").and_then(Value::as_array_mut) else {
        return false;
    };
    let Some(threat) = threats
        .iter_mut()
        .find(|threat| threat_covers_file(threat, &finding.file_path))
    else {
        return false;
    };
    push_evidence_row(threat, finding);
    if bump_threat_likelihood(threat) {
        attachment.likelihood_raised += 1;
    }
    let pattern = finding_variant_pattern(finding, threat_single_cwe(threat), read_line);
    if record_variant_pattern(threat, pattern) {
        attachment.variant_patterns += 1;
    }
    true
}

/// Detection-time evidence first; the current source line only when the
/// detector recorded no snippet. A finding without its own CWE inherits the
/// threat's when the threat names exactly one.
fn finding_variant_pattern(
    finding: &ConfirmedFindingRow,
    threat_cwe: Option<String>,
    read_line: &FindingLineReader<'_>,
) -> Value {
    let code = finding
        .evidence_snippet
        .clone()
        .or_else(|| read_line(finding));
    let cwe = finding.cwe.clone().or(threat_cwe);
    variant_pattern_json(&VariantPatternSeed {
        fingerprint: &finding.fingerprint,
        title: &finding.title,
        file_path: &finding.file_path,
        start_line: finding.start_line,
        cwe: cwe.as_deref(),
        code_line: code.as_deref(),
    })
}

fn threat_single_cwe(threat: &Value) -> Option<String> {
    let cwes = threat.get("relatedCWEs").or_else(|| threat.get("relatedCwe"))?;
    match cwes {
        Value::String(cwe) => Some(cwe.clone()),
        Value::Array(values) if values.len() == 1 => values[0].as_str().map(str::to_string),
        _ => None,
    }
}

fn threat_covers_file(threat: &Value, file_path: &str) -> bool {
    serde_json::to_string(threat)
        .map(|haystack| haystack.contains(file_path))
        .unwrap_or(false)
}

fn push_evidence_row(threat: &mut Value, finding: &ConfirmedFindingRow) {
    if !threat.get("evidence").is_some_and(Value::is_array) {
        threat["evidence"] = json!([]);
    }
    if let Some(evidence) = threat.get_mut("evidence").and_then(Value::as_array_mut) {
        evidence.push(json!({
            "kind": "finding",
            "ref": finding.fingerprint,
            "summary": finding.title,
            "addedBy": "refine",
        }));
    }
}

fn bump_threat_likelihood(threat: &mut Value) -> bool {
    let rows = threat
        .get("evidence")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let Some(base) = threat.get("likelihood").and_then(Value::as_str) else {
        return false;
    };
    let adjusted = adjusted_likelihood(base, rows, 0);
    let raised = adjusted != base;
    threat["likelihood"] = json!(adjusted);
    raised
}

fn cover_changed_surfaces(
    runtime: &dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
    verb: &str,
    input: &BuildInput,
    delta: &RefineDelta,
    generated: &mut GeneratedThreatModel,
) -> Result<(CoverageReport, &'static str)> {
    let report = check_coverage(&generated.document, &delta.changed_surfaces);
    if report.invariant_satisfied() {
        return Ok((report, "none-needed"));
    }
    if super::pipeline::staged_budget_exhausted(input, generated.cost) {
        return Ok((report, "budget-exhausted"));
    }
    run_refine_gap_fill(
        runtime,
        ctx,
        verb,
        input,
        &report,
        generated,
        &delta.code_evidence,
    )?;
    // Re-measure after remediation: the pre-gap-fill report describes the
    // document the model was asked to repair, not the one being persisted.
    let report = check_coverage(&generated.document, &delta.changed_surfaces);
    Ok((report, "stride-llm"))
}

fn run_refine_gap_fill(
    runtime: &dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
    verb: &str,
    input: &BuildInput,
    report: &CoverageReport,
    generated: &mut GeneratedThreatModel,
    code_evidence: &CodeEvidence,
) -> Result<()> {
    let outcome = run_gap_fill(
        runtime,
        ctx,
        input,
        verb,
        &report.gaps,
        &mut generated.document,
        code_evidence,
    )?;
    generated.cost = generated
        .cost
        .checked_add(outcome.cost, "refine gap-fill cost")?;
    Ok(())
}

/// Unmatched corroborated findings are surfaced honestly instead of being
/// force-fitted onto an unrelated threat: each becomes an open question for
/// the next full build or a human pass.
/// Refine stage R2 driver: skip honestly when there is nothing to close or
/// no budget left; otherwise one bounded structured call answers what the
/// evidence supports.
fn close_open_questions(
    runtime: &dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
    verb: &str,
    input: &BuildInput,
    delta: &RefineDelta,
    generated: &mut GeneratedThreatModel,
) -> Result<QuestionCloserOutcome> {
    let open = open_question_texts(&generated.document);
    if open.is_empty() {
        return Ok(QuestionCloserOutcome::skipped("none-needed", 0));
    }
    if super::pipeline::staged_budget_exhausted(input, generated.cost) {
        return Ok(QuestionCloserOutcome::skipped(
            "budget-exhausted",
            open.len(),
        ));
    }
    let outcome = run_question_closer(
        runtime,
        ctx,
        verb,
        input,
        &delta.evidence_index,
        &mut generated.document,
        &delta.code_evidence,
    )?;
    generated.cost = generated
        .cost
        .checked_add(outcome.cost, "refine question-closer cost")?;
    Ok(outcome)
}

fn record_unmatched_findings(document: &mut Value, unmatched: &[ConfirmedFindingRow]) {
    if unmatched.is_empty() {
        return;
    }
    if !document.get("openQuestions").is_some_and(Value::is_array) {
        document["openQuestions"] = json!([]);
    }
    if let Some(questions) = document
        .get_mut("openQuestions")
        .and_then(Value::as_array_mut)
    {
        for finding in unmatched {
            questions.push(json!({
                "question": format!(
                    "Corroborated finding {} at {}:{} has no covering threat; add one or deprioritize its surface.",
                    finding.fingerprint, finding.file_path, finding.start_line
                ),
                "source": "refine",
            }));
        }
    }
}

fn finalize_refined_document(
    input: &BuildInput,
    document: &mut Value,
    delta: &RefineDelta,
    attach: &EvidenceAttachment,
    coverage: &CoverageReport,
    gap_method: &str,
    closer: &QuestionCloserOutcome,
    parked: usize,
) -> Result<()> {
    restore_grounded_entry_point_facts(
        document,
        &delta.grounding_surfaces,
        &delta.entry_point_catalog.catalog_surfaces,
    )?;
    assign_stable_ids(document);
    apply_coverage(document, coverage, gap_method, parked);
    stamp_provenance(document, input.workspace_root(), "staged");
    stamp_entry_point_catalog_receipt(document, &delta.entry_point_catalog);
    stamp_refine_delta_provenance(document, delta, attach, gap_method, closer, parked);
    Ok(())
}

fn stamp_refine_delta_provenance(
    document: &mut Value,
    delta: &RefineDelta,
    attach: &EvidenceAttachment,
    gap_method: &str,
    closer: &QuestionCloserOutcome,
    parked: usize,
) {
    if let Some(provenance) = document["provenance"].as_object_mut() {
        provenance.insert("mode".to_string(), json!("refine"));
        provenance.insert(
            "refineDelta".to_string(),
            json!({
                "changedFiles": delta.changed_files.as_ref().map(Vec::len),
                "newFindings": delta.new_findings.len(),
                "attachedEvidence": attach.attached,
                "likelihoodRaised": attach.likelihood_raised,
                "variantPatterns": attach.variant_patterns,
                "unmatchedFindings": attach.unmatched.len(),
                "changedSurfaces": delta.changed_surfaces.len(),
                "entryPointCatalogChanged": delta.entry_point_catalog_changed,
                "gapFillMethod": gap_method,
                "questionsClosed": closer.questions_closed,
                "questionsOpen": closer.questions_open,
                "questionCloserMethod": closer.method,
                "parkedBySystem": parked,
            }),
        );
    }
}

fn emit_refine_delta(ctx: &ToolExecutionContext<'_>, verb: &str, delta: &RefineDelta) {
    if let Some(trace) = ctx.trace {
        let changed = delta
            .changed_files
            .as_ref()
            .map(|files| files.len().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let _ = trace
            .step(
                "tool",
                verb,
                format!(
                    "refine: {changed} changed files · {} new findings · {} changed surfaces",
                    delta.new_findings.len(),
                    delta.changed_surfaces.len()
                ),
            )
            .emit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn surface(id: &str, path: &str) -> AttackSurface {
        serde_json::from_value(json!({
            "id": id,
            "kind": "rpc_handler",
            "path": path,
            "language": "rust",
            "title": "Tauri command",
            "evidence": "#[tauri::command]",
            "risk": {"rank": 1, "score": 10, "tier": "medium", "reasons": []}
        }))
        .unwrap()
    }

    fn catalog(
        sha256: &str,
        ids: &[&str],
    ) -> crate::capabilities::entry_points::EntryPointCatalogGrounding {
        crate::capabilities::entry_points::EntryPointCatalogGrounding {
            receipt: crate::capabilities::entry_points::EntryPointCatalogReceipt {
                status: "current".to_string(),
                sha256: Some(sha256.to_string()),
                records: ids.len(),
                records_selected: ids.len(),
                grounding_limit: ids.len(),
                grounding_records_selected: ids.len(),
                snapshot_timestamp: Some(9),
                context_sha256: Some("sha256:context".to_string()),
                tree_hash: None,
                selection_policy: "risk-kind-stratified-v1".to_string(),
                revision: Some("abc".to_string()),
                revision_dirty: Some(false),
            },
            catalog_ids: ids.iter().map(|id| (*id).to_string()).collect(),
            catalog_surfaces: Vec::new(),
        }
    }

    fn row(fingerprint: &str, file: &str) -> ConfirmedFindingRow {
        ConfirmedFindingRow {
            fingerprint: fingerprint.to_string(),
            title: "OOB write".to_string(),
            file_path: file.to_string(),
            start_line: 7,
            severity: "high",
            cwe: Some("CWE-787".to_string()),
            evidence_snippet: None,
        }
    }

    #[test]
    fn new_finding_attaches_to_covering_threat_and_bumps_at_threshold() {
        let mut document = json!({
            "threats": [{
                "id": "T-1",
                "likelihood": "medium",
                "affectedFiles": [{"filePath": "src/auth.ts"}],
                "evidence": [
                    {"kind": "finding", "ref": "fp3_old1", "summary": "prior"},
                    {"kind": "finding", "ref": "fp3_old2", "summary": "prior"}
                ]
            }]
        });
        let read_line = |_: &ConfirmedFindingRow| Some("  memcpy(dst, src, len);".to_string());
        let attach = attach_new_evidence(&mut document, &[row("fp3_new", "src/auth.ts")], &read_line);
        assert_eq!(attach.attached, 1);
        assert_eq!(
            attach.likelihood_raised, 1,
            "2→3 evidence rows crosses the bump threshold"
        );
        assert!(attach.unmatched.is_empty());
        let threat = &document["threats"][0];
        assert_eq!(threat["likelihood"], json!("likely"));
        assert_eq!(threat["evidence"][2]["ref"], json!("fp3_new"));
        assert_eq!(threat["evidence"][2]["addedBy"], json!("refine"));
        assert_eq!(attach.variant_patterns, 1);
        let pattern = &threat["variantPatterns"][0];
        assert_eq!(pattern["findingRef"], json!("fp3_new"));
        assert_eq!(pattern["cwe"], json!("CWE-787"));
        assert_eq!(pattern["location"], json!("src/auth.ts:7"));
        assert_eq!(pattern["code"], json!("memcpy(dst, src, len);"));
        assert_eq!(pattern["keywords"], json!(["memcpy"]));
    }

    #[test]
    fn finding_without_covering_threat_is_unmatched_and_becomes_an_open_question() {
        let mut document = json!({"threats": [{"id": "T-1", "affectedFiles": []}]});
        let attach = attach_new_evidence(&mut document, &[row("fp3_lost", "src/other.rs")], &|_| None);
        assert_eq!(attach.attached, 0);
        assert_eq!(attach.unmatched.len(), 1);
        record_unmatched_findings(&mut document, &attach.unmatched);
        assert!(document["openQuestions"][0]["question"]
            .as_str()
            .is_some_and(|question| question.contains("fp3_lost")));
    }

    #[test]
    fn same_revision_new_catalog_digest_refreshes_bounded_catalog_surfaces() {
        let document = json!({
            "provenance": {
                "revision": "abc",
                "entryPointCatalog": {"sha256": "sha256:old"}
            }
        });
        let grounding = catalog("sha256:new", &["AS-new"]);

        let changed = catalog_digest_changed(&document, &grounding);
        let selected = refine_changed_surfaces(
            vec![
                surface("AS-new", "src/commands.rs"),
                surface("infra", "Dockerfile"),
            ],
            Some(&[]),
            changed,
            &grounding.catalog_ids,
        );

        assert!(changed);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].id, "AS-new");
    }

    #[test]
    fn unchanged_catalog_digest_preserves_zero_surface_delta() {
        let document = json!({
            "provenance": {"entryPointCatalog": {"sha256": "sha256:same"}}
        });
        let grounding = catalog("sha256:same", &["AS-existing"]);

        let changed = catalog_digest_changed(&document, &grounding);
        let selected = refine_changed_surfaces(
            vec![surface("AS-existing", "src/commands.rs")],
            None,
            changed,
            &grounding.catalog_ids,
        );

        assert!(!changed);
        assert!(selected.is_empty());
    }

    #[test]
    fn missing_prior_catalog_receipt_refreshes_catalog_surfaces() {
        let document = json!({"provenance": {"revision": "abc"}});
        let grounding = catalog("sha256:new", &["AS-new"]);

        assert!(catalog_digest_changed(&document, &grounding));
    }

    #[test]
    fn refine_finalizer_replaces_stale_coverage_and_stamps_catalog() {
        let target = tempfile::tempdir().unwrap();
        let catalog = crate::capabilities::entry_points::EntryPointCatalogGrounding {
            receipt: crate::capabilities::entry_points::EntryPointCatalogReceipt {
                status: "current".to_string(),
                sha256: Some("sha256:catalog".to_string()),
                records: 519,
                records_selected: 30,
                grounding_limit: 40,
                grounding_records_selected: 40,
                snapshot_timestamp: Some(9),
                context_sha256: Some("sha256:context".to_string()),
                tree_hash: None,
                selection_policy: "risk-kind-stratified-v1".to_string(),
                revision: Some("abc".to_string()),
                revision_dirty: Some(false),
            },
            catalog_ids: ["AS-one".to_string(), "AS-two".to_string()]
                .into_iter()
                .collect(),
            catalog_surfaces: Vec::new(),
        };
        let delta = RefineDelta {
            code_evidence: CodeEvidence::default(),
            changed_files: Some(Vec::new()),
            new_findings: Vec::new(),
            changed_surfaces: Vec::new(),
            grounding_surfaces: Vec::new(),
            entry_point_catalog: catalog,
            entry_point_catalog_changed: false,
            evidence_index: BTreeSet::new(),
        };
        let attach = EvidenceAttachment {
            attached: 0,
            likelihood_raised: 0,
            variant_patterns: 0,
            unmatched: Vec::new(),
        };
        let closer = QuestionCloserOutcome::skipped("none-needed", 0);
        let input = BuildInput {
            roots: ThreatModelBuildRoots {
                workspace_root: target.path().to_path_buf(),
                analysis_root: target.path().to_path_buf(),
                scope: None,
            },
            ..BuildInput::default()
        };
        let mut document = json!({
            "threats": [],
            "attackSurface": {"entryPoints": [{"id": "AS-one"}, {"id": "model-only"}]},
            "coverage": {"entryPointsConsidered": 0},
        });

        finalize_refined_document(
            &input,
            &mut document,
            &delta,
            &attach,
            &CoverageReport {
                considered: 2,
                gaps: vec![CoverageGap {
                    entry_point_id: "AS-two".to_string(),
                    entry_point: "second route".to_string(),
                    kind: "http_route".to_string(),
                    path: "src/two.rs".to_string(),
                }],
            },
            "none-needed",
            &closer,
            1,
        )
        .unwrap();

        assert_eq!(
            document["provenance"]["entryPointCatalog"]["records"],
            json!(519)
        );
        assert_eq!(
            document["coverage"]["catalogEntryPointsSelected"],
            json!(30)
        );
        assert_eq!(document["coverage"]["catalogEntryPointsLinked"], json!(1));
        assert_eq!(document["coverage"]["entryPointsConsidered"], json!(2));
        assert_eq!(document["coverage"]["entryPointsCovered"], json!(1));
        assert_eq!(document["coverage"]["invariantSatisfied"], json!(false));
        assert_eq!(document["coverage"]["parkedBySystem"], json!(1));
        assert_eq!(
            document["coverage"]["gaps"][0]["entryPointId"],
            json!("AS-two")
        );
        assert_eq!(
            document["provenance"]["refineDelta"]["entryPointCatalogChanged"],
            json!(false)
        );
    }
}

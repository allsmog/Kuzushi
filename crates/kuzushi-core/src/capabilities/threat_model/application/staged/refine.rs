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
    let Some(document) = try_load_persistent_threat_model(&input.target)? else {
        anyhow::bail!(
            "threat-model:build mode=refine requires a persisted .kuzushi/threat-model.json for {}; run a full build first",
            input.target.display()
        );
    };
    let source_bundle = load_threat_model_source_bundle(ctx, &input)?;
    emit_source_bundle_loaded(ctx, verb, source_bundle.loaded_count());
    let mut generated = GeneratedThreatModel {
        document,
        bridge_findings: None,
        cost_usd: 0.0,
        cost_usd_exact: true,
    };
    let delta = collect_refine_delta(&input, ctx, &generated.document)?;
    emit_refine_delta(ctx, verb, &delta);
    let attach = attach_new_evidence(&mut generated.document, &delta.new_findings);
    let gap_method = cover_changed_surfaces(runtime, ctx, verb, &input, &delta, &mut generated)?;
    let closer = close_open_questions(runtime, ctx, verb, &input, &delta, &mut generated)?;
    record_unmatched_findings(&mut generated.document, &attach.unmatched);
    finalize_refined_document(&input, &mut generated.document, &delta, &attach, gap_method, &closer);
    complete_threat_model_build(ctx, flavor, verb, input, generated, source_bundle)
}

pub(crate) struct RefineDelta {
    /// `None` = delta unknown (no recorded revision / not a git repo).
    pub(crate) changed_files: Option<Vec<String>>,
    pub(crate) new_findings: Vec<ConfirmedFindingRow>,
    pub(crate) changed_surfaces: Vec<AttackSurface>,
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
    let mut evidence_index = super::research::build_evidence_index(&grounding, &[]);
    evidence_index.extend(input.vulns.iter().map(|row| row.id.clone()));
    let cited = existing_evidence_refs(document);
    let new_findings = grounding
        .confirmed_findings
        .into_iter()
        .filter(|finding| !cited.contains(&finding.fingerprint))
        .collect();
    let changed_surfaces = changed_file_surfaces(grounding.surfaces, changed_files.as_deref());
    Ok(RefineDelta {
        changed_files,
        new_findings,
        changed_surfaces,
        evidence_index,
    })
}

fn delta_changed_files(input: &BuildInput, document: &Value) -> Result<Option<Vec<String>>> {
    let Some(revision) = document
        .pointer("/provenance/revision")
        .and_then(Value::as_str)
    else {
        return Ok(None);
    };
    changed_files_since(
        &input.target,
        revision,
        MAX_REFINE_CHANGED_FILES,
        REFINE_GIT_TIMEOUT,
    )
}

fn changed_file_surfaces(
    surfaces: Vec<AttackSurface>,
    changed_files: Option<&[String]>,
) -> Vec<AttackSurface> {
    let Some(changed) = changed_files else {
        return Vec::new();
    };
    surfaces
        .into_iter()
        .filter(|surface| changed.iter().any(|file| file == &surface.path))
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
    pub(crate) unmatched: Vec<ConfirmedFindingRow>,
}

/// Deterministic evidence attach: a new finding lands on the first threat
/// whose affectedFiles / surface text covers its file.
pub(crate) fn attach_new_evidence(
    document: &mut Value,
    new_findings: &[ConfirmedFindingRow],
) -> EvidenceAttachment {
    let mut attachment = EvidenceAttachment {
        attached: 0,
        likelihood_raised: 0,
        unmatched: Vec::new(),
    };
    for finding in new_findings {
        if attach_finding(document, finding, &mut attachment) {
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
    }
}

fn attach_finding(
    document: &mut Value,
    finding: &ConfirmedFindingRow,
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
    true
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
) -> Result<&'static str> {
    let report = check_coverage(&generated.document, &delta.changed_surfaces);
    if report.invariant_satisfied() {
        return Ok("none-needed");
    }
    if input
        .budget_usd
        .is_some_and(|budget| generated.cost_usd >= budget)
    {
        return Ok("budget-exhausted");
    }
    let outcome = run_gap_fill(
        runtime,
        ctx,
        input,
        verb,
        &report.gaps,
        &mut generated.document,
    )?;
    generated.cost_usd = crate::runtime::RuntimeCost::checked_sum(
        [generated.cost_usd, outcome.cost_usd],
        "refine gap-fill cost",
    )?
    .usd();
    generated.cost_usd_exact &= outcome.cost_usd_exact;
    Ok("stride-llm")
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
    if input
        .budget_usd
        .is_some_and(|budget| generated.cost_usd >= budget)
    {
        return Ok(QuestionCloserOutcome::skipped("budget-exhausted", open.len()));
    }
    let outcome = run_question_closer(
        runtime,
        ctx,
        verb,
        input,
        &delta.evidence_index,
        &mut generated.document,
    )?;
    generated.cost_usd = crate::runtime::RuntimeCost::checked_sum(
        [generated.cost_usd, outcome.cost_usd],
        "refine question-closer cost",
    )?
    .usd();
    generated.cost_usd_exact &= outcome.cost_usd_exact;
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
    gap_method: &str,
    closer: &QuestionCloserOutcome,
) {
    assign_stable_ids(document);
    stamp_provenance(document, &input.target, "staged");
    if let Some(provenance) = document["provenance"].as_object_mut() {
        provenance.insert("mode".to_string(), json!("refine"));
        provenance.insert(
            "refineDelta".to_string(),
            json!({
                "changedFiles": delta.changed_files.as_ref().map(Vec::len),
                "newFindings": delta.new_findings.len(),
                "attachedEvidence": attach.attached,
                "likelihoodRaised": attach.likelihood_raised,
                "unmatchedFindings": attach.unmatched.len(),
                "changedSurfaces": delta.changed_surfaces.len(),
                "gapFillMethod": gap_method,
                "questionsClosed": closer.questions_closed,
                "questionsOpen": closer.questions_open,
                "questionCloserMethod": closer.method,
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

    fn row(fingerprint: &str, file: &str) -> ConfirmedFindingRow {
        ConfirmedFindingRow {
            fingerprint: fingerprint.to_string(),
            title: "OOB write".to_string(),
            file_path: file.to_string(),
            start_line: 7,
            severity: "high",
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
        let attach = attach_new_evidence(&mut document, &[row("fp3_new", "src/auth.ts")]);
        assert_eq!(attach.attached, 1);
        assert_eq!(attach.likelihood_raised, 1, "2→3 evidence rows crosses the bump threshold");
        assert!(attach.unmatched.is_empty());
        let threat = &document["threats"][0];
        assert_eq!(threat["likelihood"], json!("likely"));
        assert_eq!(threat["evidence"][2]["ref"], json!("fp3_new"));
        assert_eq!(threat["evidence"][2]["addedBy"], json!("refine"));
    }

    #[test]
    fn finding_without_covering_threat_is_unmatched_and_becomes_an_open_question() {
        let mut document = json!({"threats": [{"id": "T-1", "affectedFiles": []}]});
        let attach = attach_new_evidence(&mut document, &[row("fp3_lost", "src/other.rs")]);
        assert_eq!(attach.attached, 0);
        assert_eq!(attach.unmatched.len(), 1);
        record_unmatched_findings(&mut document, &attach.unmatched);
        assert!(document["openQuestions"][0]["question"]
            .as_str()
            .is_some_and(|question| question.contains("fp3_lost")));
    }
}

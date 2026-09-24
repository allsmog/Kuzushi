use super::super::*;
use super::gap_fill::{run_gap_fill, GapFillOutcome};
use super::research::{research_artifact_json, research_stats, run_research, ResearchDossier};
use super::synthesis::staged_synthesis_prompt;
use super::variant_scan::{run_variant_scan, variant_scan_stats, VariantScanOutcome};
use crate::spend::{Operation, SpendLimiter, SpendTicket};

const ESTIMATED_STAGE_DEPOSIT_USD: f64 = 1.0;

struct StagedBuildOutput {
    generated: GeneratedThreatModel,
    source_bundle: ThreatModelSourceBundle,
    reconciliation: BuildReconciliation,
}

/// Staged pipeline: R research (deterministic) → S synthesis+generalize
/// (1 LLM call) → V coverage validation (deterministic) → G conditional
/// STRIDE gap-fill (≤1 LLM call) → E emit through the shared build tail.
pub(crate) fn build_staged_threat_model(
    runtime: &dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
    verb: &str,
    input: BuildInput,
) -> Result<Value> {
    let checkpoints = ctx.stage_checkpoints();
    let (source_bundle, dossier) = run_staged_research_stage(ctx, verb, &input, &checkpoints)?;
    let spend = staged_spend_limiter(ctx)?;
    let (mut generated, evidence_warnings) = run_staged_synthesis_stage(
        runtime,
        ctx,
        flavor,
        verb,
        &input,
        &source_bundle,
        &dossier,
        spend.as_ref(),
        &checkpoints,
    )?;
    let reconciliation = run_staged_post_synthesis(
        runtime,
        ctx,
        verb,
        &input,
        &dossier,
        &mut generated,
        spend.as_ref(),
        evidence_warnings,
        &checkpoints,
    )?;
    let output = StagedBuildOutput {
        generated,
        source_bundle,
        reconciliation,
    };
    complete_staged_build(ctx, flavor, verb, input, output)
}

fn complete_staged_build(
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
    verb: &str,
    input: BuildInput,
    output: StagedBuildOutput,
) -> Result<Value> {
    complete_threat_model_build(
        ctx,
        flavor,
        verb,
        input,
        output.generated,
        output.source_bundle,
        output.reconciliation,
    )
}

fn run_staged_research_stage(
    ctx: &ToolExecutionContext<'_>,
    verb: &str,
    input: &BuildInput,
    checkpoints: &Option<std::sync::Arc<crate::run_artifacts::StageCheckpointHandle>>,
) -> Result<(ThreatModelSourceBundle, ResearchDossier)> {
    let mut source_bundle = load_threat_model_source_bundle(ctx, input)?;
    emit_seed_disclosure(ctx, verb, input)?;
    let research_stage = stage_scope(checkpoints, "research");
    let mut dossier = run_research(input, ctx)?;
    source_bundle
        .authenticate_entry_point_sources(&dossier.grounding.entry_point_catalog.receipt)?;
    dossier.code_evidence = source_bundle.attach_source_code(
        input,
        &dossier.grounding.surfaces,
        dossier
            .grounding
            .entry_point_catalog
            .receipt
            .tree_hash
            .as_deref(),
        ctx,
    )?;
    dossier
        .evidence_index
        .extend(dossier.code_evidence.references.iter().cloned());
    emit_source_bundle_loaded(ctx, verb, source_bundle.loaded_count());
    emit_research(ctx, verb, &dossier);
    write_stage_artifact(
        input.workspace_root(),
        &input.output_dir,
        "research.json",
        &research_artifact_json(&dossier),
    )?;
    complete_stage(
        research_stage,
        vec![stage_artifact_rel(input, "research.json")],
    );
    Ok((source_bundle, dossier))
}

#[allow(clippy::too_many_arguments)]
fn run_staged_synthesis_stage(
    runtime: &dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
    verb: &str,
    input: &BuildInput,
    source_bundle: &ThreatModelSourceBundle,
    dossier: &ResearchDossier,
    spend: Option<&SpendLimiter>,
    checkpoints: &Option<std::sync::Arc<crate::run_artifacts::StageCheckpointHandle>>,
) -> Result<(GeneratedThreatModel, Vec<String>)> {
    let synthesis_stage = stage_scope(checkpoints, "synthesis");
    let mut generated = run_synthesis(
        runtime,
        ctx,
        flavor,
        verb,
        input,
        source_bundle,
        dossier,
        spend,
    )?;
    complete_stage(synthesis_stage, Vec::new());
    let warnings = validate_synthesis_document(&mut generated.document, dossier);
    Ok((generated, warnings))
}

#[allow(clippy::too_many_arguments)]
fn run_staged_post_synthesis(
    runtime: &dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
    verb: &str,
    input: &BuildInput,
    dossier: &ResearchDossier,
    generated: &mut GeneratedThreatModel,
    spend: Option<&SpendLimiter>,
    evidence_warnings: Vec<String>,
    checkpoints: &Option<std::sync::Arc<crate::run_artifacts::StageCheckpointHandle>>,
) -> Result<BuildReconciliation> {
    let gapfill_stage = stage_scope(checkpoints, "gapfill");
    let gap_fill = resolve_coverage(runtime, ctx, verb, input, dossier, generated, spend)?;
    let variants = run_optional_variant_scan(ctx, verb, input, generated)?;
    let reconciliation = finalize_staged_document(
        input,
        dossier,
        generated,
        &gap_fill,
        variants,
        evidence_warnings,
    )?;
    complete_stage(
        gapfill_stage,
        vec![
            stage_artifact_rel(input, "coverage.json"),
            stage_artifact_rel(input, "gapfill.json"),
        ],
    );
    Ok(reconciliation)
}

pub(crate) fn stage_scope<'a>(
    checkpoints: &'a Option<std::sync::Arc<crate::run_artifacts::StageCheckpointHandle>>,
    stage: &str,
) -> Option<crate::run_artifacts::StageGuard<'a>> {
    checkpoints.as_ref().map(|handle| handle.stage(stage))
}

pub(crate) fn complete_stage(
    guard: Option<crate::run_artifacts::StageGuard<'_>>,
    artifacts: Vec<String>,
) {
    if let Some(guard) = guard {
        guard.complete(artifacts);
    }
}

fn stage_artifact_rel(input: &BuildInput, leaf: &str) -> String {
    format!("{}/{leaf}", input.output_dir.trim_end_matches('/'))
}

#[allow(clippy::too_many_arguments)]
fn run_synthesis(
    runtime: &dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
    verb: &str,
    input: &BuildInput,
    source_bundle: &ThreatModelSourceBundle,
    dossier: &ResearchDossier,
    spend: Option<&SpendLimiter>,
) -> Result<GeneratedThreatModel> {
    let prompt = staged_synthesis_prompt(input, source_bundle, dossier)?;
    let ticket = reserve_stage_budget(spend)?;
    let costed = query_threat_model_document(runtime, ctx, flavor, verb, input, prompt);
    settle_stage_budget(spend, ticket, &costed)?;
    let costed = costed?;
    let mut generated = normalize_threat_model_raw(costed.value, &input.methodology)?;
    generated.cost_usd = costed.cost_usd;
    generated.cost_usd_exact = costed.cost_usd_exact;
    Ok(generated)
}

fn validate_synthesis_document(document: &mut Value, dossier: &ResearchDossier) -> Vec<String> {
    let warnings = retain_indexed_evidence(document, &dossier.evidence_index);
    apply_evidence_likelihood(document);
    warnings
}

struct GapFillResolution {
    report: CoverageReport,
    method: &'static str,
    artifact: Value,
}

enum GapFillBudget {
    Reserved(Option<SpendTicket>),
    Exhausted(String),
}

fn resolve_coverage(
    runtime: &dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
    verb: &str,
    input: &BuildInput,
    dossier: &ResearchDossier,
    generated: &mut GeneratedThreatModel,
    spend: Option<&SpendLimiter>,
) -> Result<GapFillResolution> {
    let report = check_coverage(&generated.document, &dossier.grounding.surfaces);
    emit_coverage_checked(ctx, verb, &report);
    if report.invariant_satisfied() {
        return Ok(GapFillResolution {
            report,
            method: "none-needed",
            artifact: json!({"ran": false, "reason": "no gaps"}),
        });
    }
    if budget_exhausted(input, generated.cost_usd) {
        return Ok(GapFillResolution {
            report,
            method: "budget-exhausted",
            artifact: json!({"ran": false, "reason": "budget exhausted before gap-fill"}),
        });
    }
    gap_fill_resolution(runtime, ctx, verb, input, dossier, generated, spend, report)
}

#[allow(clippy::too_many_arguments)]
fn gap_fill_resolution(
    runtime: &dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
    verb: &str,
    input: &BuildInput,
    dossier: &ResearchDossier,
    generated: &mut GeneratedThreatModel,
    spend: Option<&SpendLimiter>,
    report: CoverageReport,
) -> Result<GapFillResolution> {
    let ticket = match reserve_gap_fill_budget(spend)? {
        GapFillBudget::Reserved(ticket) => ticket,
        GapFillBudget::Exhausted(reason) => {
            return Ok(skipped_gap_fill_resolution(report, reason));
        }
    };
    let outcome = run_gap_fill(
        runtime,
        ctx,
        input,
        verb,
        &report.gaps,
        &mut generated.document,
        &dossier.code_evidence,
    )?;
    record_gap_fill_cost(spend, ticket, generated, &outcome)?;
    let after = check_coverage(&generated.document, &dossier.grounding.surfaces);
    emit_coverage_checked(ctx, verb, &after);
    Ok(completed_gap_fill_resolution(after, &outcome))
}

fn reserve_gap_fill_budget(spend: Option<&SpendLimiter>) -> Result<GapFillBudget> {
    match reserve_stage_budget(spend) {
        Ok(ticket) => Ok(GapFillBudget::Reserved(ticket)),
        Err(error) if is_spend_cap_exhausted(&error) => {
            Ok(GapFillBudget::Exhausted(format!("{error:#}")))
        }
        Err(error) => Err(error),
    }
}

fn skipped_gap_fill_resolution(report: CoverageReport, reason: String) -> GapFillResolution {
    GapFillResolution {
        report,
        method: "budget-exhausted",
        artifact: json!({"ran": false, "reason": reason}),
    }
}

fn record_gap_fill_cost(
    spend: Option<&SpendLimiter>,
    ticket: Option<SpendTicket>,
    generated: &mut GeneratedThreatModel,
    outcome: &GapFillOutcome,
) -> Result<()> {
    settle_gap_fill_cost(spend, ticket, outcome.cost_usd)?;
    generated.cost_usd = crate::runtime::RuntimeCost::checked_sum(
        [generated.cost_usd, outcome.cost_usd],
        "staged threat-model cost",
    )?
    .usd();
    generated.cost_usd_exact &= outcome.cost_usd_exact;
    Ok(())
}

fn completed_gap_fill_resolution(
    report: CoverageReport,
    outcome: &GapFillOutcome,
) -> GapFillResolution {
    GapFillResolution {
        artifact: json!({
            "ran": true,
            "addedThreats": outcome.added_threats,
            "addedDeprioritized": outcome.added_deprioritized,
            "addedEntryPoints": outcome.added_entry_points,
            "residualGaps": report.gaps.len(),
        }),
        method: "stride-llm",
        report,
    }
}

fn run_optional_variant_scan(
    ctx: &ToolExecutionContext<'_>,
    verb: &str,
    input: &BuildInput,
    generated: &mut GeneratedThreatModel,
) -> Result<Option<VariantScanOutcome>> {
    if !input.variant_scan {
        return Ok(None);
    }
    let outcome = run_variant_scan(input.analysis_root(), &mut generated.document)?;
    rebase_variant_scan_samples(input, &mut generated.document);
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                verb,
                format!(
                    "variant scan: {} threats with patterns · {} siblings · likelihood raised on {}",
                    outcome.threats_with_patterns,
                    outcome.total_siblings,
                    outcome.likelihood_raised
                ),
            )
            .emit();
    }
    Ok(Some(outcome))
}

fn rebase_variant_scan_samples(input: &BuildInput, document: &mut Value) {
    let Some(scope) = input
        .roots
        .scope
        .as_ref()
        .filter(|scope| scope.rel_path != Path::new("."))
    else {
        return;
    };
    let Some(threats) = document.get_mut("threats").and_then(Value::as_array_mut) else {
        return;
    };
    for sample in threats
        .iter_mut()
        .filter_map(|threat| threat.pointer_mut("/variantScan/siblingSample"))
        .filter_map(Value::as_array_mut)
        .flatten()
    {
        let Some(path) = sample.as_str() else {
            continue;
        };
        *sample = json!(scope
            .rel_path
            .join(path)
            .to_string_lossy()
            .replace('\\', "/"));
    }
}

fn finalize_staged_document(
    input: &BuildInput,
    dossier: &ResearchDossier,
    generated: &mut GeneratedThreatModel,
    gap_fill: &GapFillResolution,
    variants: Option<VariantScanOutcome>,
    evidence_warnings: Vec<String>,
) -> Result<BuildReconciliation> {
    let parked = stamp_staged_document(
        input,
        dossier,
        generated,
        gap_fill,
        variants.as_ref(),
        evidence_warnings,
    )?;
    write_staged_resolution_artifacts(input, gap_fill, parked)?;
    Ok(BuildReconciliation::from_report(
        &gap_fill.report,
        parked,
        "grounded surfaces",
        &generated.document,
    ))
}

fn stamp_staged_document(
    input: &BuildInput,
    dossier: &ResearchDossier,
    generated: &mut GeneratedThreatModel,
    gap_fill: &GapFillResolution,
    variants: Option<&VariantScanOutcome>,
    evidence_warnings: Vec<String>,
) -> Result<usize> {
    restore_grounded_entry_point_facts(
        &mut generated.document,
        &dossier.grounding.surfaces,
        &dossier.grounding.entry_point_catalog.catalog_surfaces,
    )?;
    assign_stable_ids(&mut generated.document);
    let parked = park_unaccounted(&mut generated.document, &gap_fill.report.gaps);
    apply_coverage(
        &mut generated.document,
        &gap_fill.report,
        gap_fill.method,
        parked,
    );
    stamp_grounding_selection(&mut generated.document, &dossier.grounding.selection);
    stamp_entry_point_catalog_receipt(
        &mut generated.document,
        &dossier.grounding.entry_point_catalog,
    );
    stamp_staged_run_provenance(&mut generated.document, input, dossier, variants);
    if !evidence_warnings.is_empty() {
        generated.document["evidenceWarnings"] = json!(evidence_warnings);
    }
    Ok(parked)
}

fn stamp_staged_run_provenance(
    document: &mut Value,
    input: &BuildInput,
    dossier: &ResearchDossier,
    variants: Option<&VariantScanOutcome>,
) {
    stamp_provenance(document, input.workspace_root(), "staged");
    let Some(provenance) = document["provenance"].as_object_mut() else {
        return;
    };
    provenance.insert("researchStats".to_string(), research_stats(dossier));
    if let Some(variants) = variants {
        provenance.insert("variantScan".to_string(), variant_scan_stats(variants));
    }
}

fn write_staged_resolution_artifacts(
    input: &BuildInput,
    gap_fill: &GapFillResolution,
    parked: usize,
) -> Result<()> {
    write_stage_artifact(
        input.workspace_root(),
        &input.output_dir,
        "coverage.json",
        &coverage_json(&gap_fill.report, gap_fill.method, parked),
    )?;
    write_stage_artifact(
        input.workspace_root(),
        &input.output_dir,
        "gapfill.json",
        &gap_fill.artifact,
    )?;
    Ok(())
}

fn emit_research(ctx: &ToolExecutionContext<'_>, verb: &str, dossier: &ResearchDossier) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                verb,
                format!(
                    "research: {} · {} vuln commits · {} confirmed findings",
                    dossier.grounding.selection.surfaces_label(),
                    dossier.vuln_commits.len(),
                    dossier.grounding.confirmed_findings.len()
                ),
            )
            .emit();
    }
}

fn budget_exhausted(input: &BuildInput, spent_usd: f64) -> bool {
    input.budget_usd.is_some_and(|budget| spent_usd >= budget)
}

/// Workspace spend-ledger protection (hard ceiling + operator caps), same
/// shape as full-mode chunks: deposit an estimate, refund to actual.
fn staged_spend_limiter(ctx: &ToolExecutionContext<'_>) -> Result<Option<SpendLimiter>> {
    ctx.workspace
        .map(|workspace| {
            SpendLimiter::open_with_hard_ceiling(
                workspace.findings_db_path(),
                ctx.config.operator.spend_hard_ceiling_usd,
            )
        })
        .transpose()
}

fn reserve_stage_budget(spend: Option<&SpendLimiter>) -> Result<Option<SpendTicket>> {
    match spend {
        Some(limiter) => limiter
            .deposit(Operation::ThreatModelStaged, ESTIMATED_STAGE_DEPOSIT_USD)
            .context("threat-model staged: spend deposit failed")
            .map(Some),
        None => Ok(None),
    }
}

fn settle_stage_budget(
    spend: Option<&SpendLimiter>,
    ticket: Option<SpendTicket>,
    costed: &Result<crate::structured_output::CostedStructuredJson<Value>>,
) -> Result<()> {
    let actual = match costed {
        Ok(costed) => costed.cost_usd,
        Err(_) => 0.0,
    };
    settle_gap_fill_cost(spend, ticket, actual)
}

fn settle_gap_fill_cost(
    spend: Option<&SpendLimiter>,
    ticket: Option<SpendTicket>,
    actual_usd: f64,
) -> Result<()> {
    if let (Some(limiter), Some(ticket)) = (spend, ticket) {
        limiter.refund(ticket, actual_usd)?;
    }
    Ok(())
}

fn is_spend_cap_exhausted(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<crate::spend::SpendError>(),
        Some(
            crate::spend::SpendError::Exceeded { .. }
                | crate::spend::SpendError::HardCeilingExceeded { .. }
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog_grounding() -> crate::capabilities::entry_points::EntryPointCatalogGrounding {
        crate::capabilities::entry_points::EntryPointCatalogGrounding {
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
                revision: None,
                revision_dirty: None,
            },
            catalog_ids: ["AS-one".to_string()].into_iter().collect(),
            catalog_surfaces: Vec::new(),
        }
    }

    #[test]
    fn staged_finalizer_stamps_catalog_receipt_and_coverage_counts() {
        let target = tempfile::tempdir().unwrap();
        let input = BuildInput {
            roots: ThreatModelBuildRoots {
                workspace_root: target.path().to_path_buf(),
                analysis_root: target.path().to_path_buf(),
                scope: None,
            },
            output_dir: "artifacts".to_string(),
            ..BuildInput::default()
        };
        let dossier = ResearchDossier {
            code_evidence: CodeEvidence::default(),
            grounding: PromptGrounding {
                surfaces: Vec::new(),
                confirmed_findings: Vec::new(),
                entry_point_catalog: catalog_grounding(),
                selection: GroundingSelection::default(),
            },
            vuln_commits: Vec::new(),
            history_mined: false,
            advisories: Vec::new(),
            docs: Vec::new(),
            operator_vulns: Vec::new(),
            evidence_index: BTreeSet::new(),
        };
        let mut generated = GeneratedThreatModel {
            document: json!({
                "threats": [],
                "attackSurface": {"entryPoints": [{"id": "AS-one"}]},
            }),
            bridge_findings: None,
            cost_usd: 0.0,
            cost_usd_exact: true,
        };
        let gap_fill = GapFillResolution {
            report: CoverageReport {
                considered: 0,
                gaps: Vec::new(),
            },
            method: "none-needed",
            artifact: json!({"ran": false}),
        };

        finalize_staged_document(
            &input,
            &dossier,
            &mut generated,
            &gap_fill,
            None,
            Vec::new(),
        )
        .unwrap();

        assert_eq!(
            generated.document["provenance"]["entryPointCatalog"]["records"],
            json!(519)
        );
        assert_eq!(
            generated.document["coverage"]["catalogEntryPointsSelected"],
            json!(30)
        );
        assert_eq!(
            generated.document["coverage"]["catalogEntryPointsLinked"],
            json!(1)
        );
    }

    #[test]
    fn scoped_variant_samples_are_rebased_to_workspace_relative_paths() {
        let target = tempfile::tempdir().unwrap();
        let input = BuildInput {
            roots: ThreatModelBuildRoots {
                workspace_root: target.path().to_path_buf(),
                analysis_root: target.path().join("services/api"),
                scope: Some(ScopeRef {
                    scope_id: "scope_api".to_string(),
                    rel_path: PathBuf::from("services/api"),
                    project_model_sha256: format!("sha256:{}", "a".repeat(64)),
                    target_revision: "fixture".to_string(),
                }),
            },
            ..BuildInput::default()
        };
        let mut document = json!({
            "threats": [{
                "variantScan": {
                    "siblingSample": ["src/one.rs", "src/two.rs"]
                }
            }]
        });

        rebase_variant_scan_samples(&input, &mut document);

        assert_eq!(
            document["threats"][0]["variantScan"]["siblingSample"],
            json!(["services/api/src/one.rs", "services/api/src/two.rs"])
        );
    }
}

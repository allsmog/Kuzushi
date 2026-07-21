use super::super::*;
use super::gap_fill::run_gap_fill;
use super::research::{research_artifact_json, research_stats, run_research, ResearchDossier};
use super::synthesis::staged_synthesis_prompt;
use crate::spend::{Operation, SpendLimiter, SpendTicket};

const ESTIMATED_STAGE_DEPOSIT_USD: f64 = 1.0;

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
    let source_bundle = load_threat_model_source_bundle(ctx, &input)?;
    emit_source_bundle_loaded(ctx, verb, source_bundle.loaded_count());
    let dossier = run_research(&input, ctx)?;
    emit_research(ctx, verb, &dossier);
    write_stage_artifact(
        &input.target,
        &input.output_dir,
        "research.json",
        &research_artifact_json(&dossier),
    )?;
    let spend = staged_spend_limiter(ctx)?;
    let mut generated = run_synthesis(runtime, ctx, flavor, verb, &input, &source_bundle, &dossier, spend.as_ref())?;
    let evidence_warnings = validate_synthesis_document(&mut generated.document, &dossier);
    let gap_fill = resolve_coverage(runtime, ctx, verb, &input, &dossier, &mut generated, spend.as_ref())?;
    finalize_staged_document(&input, &dossier, &mut generated, &gap_fill, evidence_warnings)?;
    complete_threat_model_build(ctx, flavor, verb, input, generated, source_bundle)
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
    let ticket = match reserve_stage_budget(spend) {
        Ok(ticket) => ticket,
        Err(error) if is_spend_cap_exhausted(&error) => {
            return Ok(GapFillResolution {
                report,
                method: "budget-exhausted",
                artifact: json!({"ran": false, "reason": format!("{error:#}")}),
            });
        }
        Err(error) => return Err(error),
    };
    let outcome = run_gap_fill(runtime, ctx, input, verb, &report.gaps, &mut generated.document);
    if let Ok(outcome) = &outcome {
        settle_gap_fill_cost(spend, ticket, outcome.cost_usd)?;
        generated.cost_usd = crate::runtime::RuntimeCost::checked_sum(
            [generated.cost_usd, outcome.cost_usd],
            "staged threat-model cost",
        )?
        .usd();
        generated.cost_usd_exact &= outcome.cost_usd_exact;
    }
    let outcome = outcome?;
    let after = check_coverage(&generated.document, &dossier.grounding.surfaces);
    emit_coverage_checked(ctx, verb, &after);
    Ok(GapFillResolution {
        artifact: json!({
            "ran": true,
            "addedThreats": outcome.added_threats,
            "addedDeprioritized": outcome.added_deprioritized,
            "residualGaps": after.gaps.len(),
        }),
        method: "stride-llm",
        report: after,
    })
}

fn finalize_staged_document(
    input: &BuildInput,
    dossier: &ResearchDossier,
    generated: &mut GeneratedThreatModel,
    gap_fill: &GapFillResolution,
    evidence_warnings: Vec<String>,
) -> Result<()> {
    assign_stable_ids(&mut generated.document);
    apply_coverage(&mut generated.document, &gap_fill.report, gap_fill.method);
    stamp_provenance(&mut generated.document, &input.target, "staged");
    if let Some(provenance) = generated.document["provenance"].as_object_mut() {
        provenance.insert("researchStats".to_string(), research_stats(dossier));
    }
    if !evidence_warnings.is_empty() {
        generated.document["evidenceWarnings"] = json!(evidence_warnings);
    }
    write_stage_artifact(
        &input.target,
        &input.output_dir,
        "coverage.json",
        &coverage_json(&gap_fill.report, gap_fill.method),
    )?;
    write_stage_artifact(
        &input.target,
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
                    "research: {} surfaces · {} vuln commits · {} confirmed findings",
                    dossier.grounding.surfaces.len(),
                    dossier.vuln_commits.len(),
                    dossier.grounding.confirmed_findings.len()
                ),
            )
            .emit();
    }
}

fn budget_exhausted(input: &BuildInput, spent_usd: f64) -> bool {
    input
        .budget_usd
        .is_some_and(|budget| spent_usd >= budget)
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

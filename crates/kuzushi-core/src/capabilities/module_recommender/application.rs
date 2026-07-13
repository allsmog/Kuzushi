use super::model_ranking::ModelRanking;
use super::rule_catalog::recommendation_rules;
use super::*;

/// Build the report, preferring session-model ranking when available and
/// falling back to the deterministic rule catalog otherwise (clearly labeled).
pub(crate) fn build_recommendation_report_ranked(
    request: RecommenderRequest,
    ranking: ModelRanking<'_>,
) -> RecommendationReport {
    let outcome = ranking.rank(&request);
    match outcome.recommendations.clone() {
        Some(recommendations) => model_report(request, recommendations, outcome),
        None => fallback_report(request, outcome),
    }
}

fn model_report(
    request: RecommenderRequest,
    recommendations: Vec<ModuleRecommendation>,
    outcome: super::model_ranking::ModelRankingOutcome,
) -> RecommendationReport {
    let recommendations = demote_blocked_scanners(&request, recommendations);
    let warnings = warnings_for(&request);
    let components = request.components.clone();
    let summary = format!(
        "Recommended {} module tool(s) for {} — ranked by {}.",
        recommendations.len(),
        request.target,
        outcome.model.as_deref().unwrap_or("the session model")
    );
    RecommendationReport {
        ok: true,
        summary,
        target: request.target,
        signals: request.signals,
        capabilities: CapabilitySummary {
            available_tool_count: request.available_tools.len(),
            recommended_tool_count: recommendations.len(),
            skipped_missing_tools: Vec::new(),
        },
        recommendations,
        components,
        cost_usd: outcome.cost.observed_usd(),
        cost_usd_exact: outcome.cost.is_complete(),
        provider_spend_unresolved: outcome.provider_spend_unresolved,
        warnings,
        errors: Vec::new(),
    }
}

pub(crate) fn build_recommendation_report(request: RecommenderRequest) -> RecommendationReport {
    let candidates = recommendation_rules()
        .iter()
        .filter(|rule| (rule.condition)(&request.signals))
        .collect::<Vec<_>>();
    let skipped_missing_tools = missing_tool_names(&request, &candidates);
    let recommendations = candidates
        .into_iter()
        .filter(|rule| request.available_tools.contains(rule.tool))
        .map(|rule| recommendation_from_rule(rule, &request))
        .collect::<Vec<_>>();
    let mut recommendations = demote_blocked_scanners(&request, recommendations);
    recommendations.sort_by_key(recommendation_sort_key);
    recommendations.truncate(request.max_recommendations);
    let warnings = warnings_for(&request);
    let components = request.components.clone();

    RecommendationReport {
        ok: true,
        summary: report_summary(&request, recommendations.len()),
        target: request.target,
        signals: request.signals,
        capabilities: CapabilitySummary {
            available_tool_count: request.available_tools.len(),
            recommended_tool_count: recommendations.len(),
            skipped_missing_tools,
        },
        recommendations,
        components,
        cost_usd: 0.0,
        cost_usd_exact: true,
        provider_spend_unresolved: false,
        warnings,
        errors: Vec::new(),
    }
}

fn fallback_report(
    request: RecommenderRequest,
    outcome: super::model_ranking::ModelRankingOutcome,
) -> RecommendationReport {
    let mut report = build_recommendation_report(request);
    report.cost_usd = outcome.cost.observed_usd();
    report.cost_usd_exact = outcome.cost.is_complete();
    report.provider_spend_unresolved = outcome.provider_spend_unresolved;
    if let Some(reason) = outcome.fallback_reason {
        report.warnings.push(format!(
            "model ranking was not used; deterministic catalog fallback: {reason}"
        ));
    }
    report
}

fn recommendation_from_rule(
    rule: &RecommendationRule,
    request: &RecommenderRequest,
) -> ModuleRecommendation {
    let next_input = (rule.next_input)(request);
    ModuleRecommendation {
        module_id: module_id_for_tool(rule.tool).to_string(),
        tool: rule.tool.to_string(),
        priority: rule.priority,
        reason: rule.reason.to_string(),
        signals: (rule.signals)(&request.signals),
        requires_runtime: crate::modules::tool_needs_runtime(rule.tool, &next_input),
        next_input,
    }
}

/// A recommendation whose scanner binary is missing can only fail as
/// dispatched. Keep it visible (installing the binary is a legitimate next
/// move) but sink it to Low and lead the reason with the blocker, so the
/// operator is never ranked straight into a "binary not found" error.
fn demote_blocked_scanners(
    request: &RecommenderRequest,
    recommendations: Vec<ModuleRecommendation>,
) -> Vec<ModuleRecommendation> {
    recommendations
        .into_iter()
        .map(|mut recommendation| {
            if request
                .tools_missing_binaries
                .contains(&recommendation.tool)
            {
                recommendation.priority = RecommendationPriority::Low;
                recommendation.reason = format!(
                    "blocked: scanner binary not on PATH — install it first. {}",
                    recommendation.reason
                );
            }
            recommendation
        })
        .collect()
}

fn recommendation_sort_key(recommendation: &ModuleRecommendation) -> (u8, String) {
    (
        recommendation.priority.sort_key(),
        recommendation.tool.clone(),
    )
}

fn missing_tool_names(
    request: &RecommenderRequest,
    candidates: &[&RecommendationRule],
) -> Vec<String> {
    candidates
        .iter()
        .filter(|rule| !request.available_tools.contains(rule.tool))
        .map(|rule| rule.tool.to_string())
        .collect()
}

fn report_summary(request: &RecommenderRequest, count: usize) -> String {
    format!(
        "Recommended {count} module tool(s) for {} from repository, attack-surface, threat-model, capability, and finding signals.",
        request.target
    )
}

fn warnings_for(request: &RecommenderRequest) -> Vec<String> {
    let mut warnings = Vec::new();
    push_findings_store_warning(&mut warnings, &request.signals);
    warnings
}

fn push_findings_store_warning(warnings: &mut Vec<String>, signals: &RepositorySignals) {
    if !signals.findings_available {
        warnings.push(
            "findings store unavailable; finding-state follow-up recommendations were omitted"
                .to_string(),
        );
    }
}

fn module_id_for_tool(tool: &str) -> &str {
    tool.split_once(':')
        .map(|(module, _)| module)
        .unwrap_or(tool)
}

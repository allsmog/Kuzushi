use super::threat_model_signals::{
    threat_model_array_count, threat_model_dfd_count, threat_model_related_cwes,
    threat_signal_count,
};
use super::*;
use crate::strategy::{
    apply_strategy_corrections, load_strategy_queue, save_strategy_queue, StrategyPhase,
    StrategyPreflight, StrategyPreflightStatus, StrategyProposal, StrategyProposalStatus,
    StrategyResourceRisk,
};

pub(crate) fn execute_module_recommender_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    available_tools: Vec<String>,
) -> Result<Value> {
    let workspace = workspace_for_input(&input, ctx)?;
    let inventory = build_repository_inventory(workspace.root())?;
    let attack_surface = build_attack_surface_map_from_inventory(workspace.root(), &inventory)?;
    let threat_model = load_persistent_threat_model(workspace.root());
    let (findings_available, findings) = list_findings(ctx, &workspace)?;
    let request = RecommenderRequest {
        target: workspace.root().display().to_string(),
        max_recommendations: max_recommendations(&input),
        available_tools: available_tools.into_iter().collect(),
        tools_missing_binaries: tools_missing_binaries(),
        signals: repository_signals(
            workspace.root(),
            &inventory,
            &attack_surface,
            threat_model.as_ref(),
            findings_available,
            &findings,
        ),
    };
    // Rank with the session model when one is configured and a runtime is
    // available; otherwise fall back to the deterministic rule catalog.
    let ranking = ModelRanking::resolve(ctx, runtime, &input, workspace.root());
    let report = build_recommendation_report_ranked(request, ranking);
    let strategy_proposals = persist_strategy_proposals(&workspace, &report, ctx.run_id())?;
    write_strategy_run_artifact(ctx, &strategy_proposals)?;
    let summary = report.summary.clone();
    let output = recommendation_report_output(&report);
    let data =
        serde_json::to_value(report).context("Could not serialize module recommendations")?;
    Ok(crate::module_result::completed_output_result(
        summary, output, data,
    ))
}

fn persist_strategy_proposals(
    workspace: &WorkspaceTarget,
    report: &RecommendationReport,
    run_id: Option<String>,
) -> Result<Vec<StrategyProposal>> {
    let mut existing = load_strategy_queue(workspace)?;
    let now = strategy_now_ms();
    let mut generated_ids = Vec::new();
    let mut generated = Vec::new();
    for recommendation in &report.recommendations {
        let proposal = strategy_proposal_from_recommendation(recommendation, run_id.clone(), now);
        generated_ids.push(proposal.id.clone());
        generated.push(proposal);
    }
    apply_strategy_corrections(workspace, run_id.as_deref(), &mut generated)?;
    for proposal in generated {
        merge_strategy_proposal(&mut existing, proposal);
    }
    save_strategy_queue(workspace, &existing)?;
    Ok(existing
        .into_iter()
        .filter(|proposal| generated_ids.contains(&proposal.id))
        .collect())
}

fn write_strategy_run_artifact(
    ctx: &ToolExecutionContext<'_>,
    proposals: &[StrategyProposal],
) -> Result<()> {
    let Some((target, run_id)) = ctx.run_artifact_location() else {
        return Ok(());
    };
    let value = serde_json::json!({
        "source": "module-recommender:recommend",
        "strategyProposals": proposals,
    });
    crate::run_artifacts::write_run_artifact_json(
        target,
        &run_id,
        "strategy.json",
        "strategy proposals",
        &value,
    )?;
    Ok(())
}

fn merge_strategy_proposal(
    proposals: &mut Vec<StrategyProposal>,
    mut next: StrategyProposal,
) {
    if let Some(existing) = proposals
        .iter_mut()
        .find(|proposal| proposal.id == next.id)
    {
        next.status = existing.status;
        next.created_at_ms = existing.created_at_ms;
        *existing = next;
    } else {
        proposals.push(next);
    }
}

fn strategy_proposal_from_recommendation(
    recommendation: &ModuleRecommendation,
    run_id: Option<String>,
    now: u64,
) -> StrategyProposal {
    let blocked = recommendation.reason.starts_with("blocked:");
    StrategyProposal {
        id: format!("review-{}", strategy_tool_slug(&recommendation.tool)),
        phase: StrategyPhase::Review,
        base_strategy: "module recommender defaults".to_string(),
        recommended_strategy: format!("run {}", recommendation.tool),
        corrected_strategy: None,
        applied_corrections: Vec::new(),
        rationale: recommendation.reason.clone(),
        expected_cost_usd: None,
        expected_runtime: Some(strategy_runtime_estimate(recommendation).to_string()),
        preflight: strategy_preflight(recommendation, blocked),
        resource_risk: strategy_resource_risk(recommendation, blocked),
        status: StrategyProposalStatus::Proposed,
        source_run_id: run_id,
        tool: Some(recommendation.tool.clone()),
        next_input: Some(recommendation.next_input.clone()),
        created_at_ms: now,
        updated_at_ms: now,
    }
}

fn strategy_preflight(
    recommendation: &ModuleRecommendation,
    blocked: bool,
) -> StrategyPreflight {
    if blocked {
        return StrategyPreflight {
            status: StrategyPreflightStatus::Blocked,
            notes: vec![recommendation.reason.clone()],
        };
    }
    StrategyPreflight {
        status: StrategyPreflightStatus::Ready,
        notes: recommendation.signals.iter().take(3).cloned().collect(),
    }
}

fn strategy_resource_risk(
    recommendation: &ModuleRecommendation,
    blocked: bool,
) -> StrategyResourceRisk {
    if blocked {
        return StrategyResourceRisk::Blocked;
    }
    if recommendation.requires_runtime {
        return StrategyResourceRisk::Medium;
    }
    match recommendation.priority {
        RecommendationPriority::High => StrategyResourceRisk::Medium,
        RecommendationPriority::Medium => StrategyResourceRisk::Low,
        RecommendationPriority::Low => StrategyResourceRisk::Low,
    }
}

fn strategy_runtime_estimate(recommendation: &ModuleRecommendation) -> &'static str {
    if recommendation.requires_runtime {
        "model-assisted pass"
    } else {
        "local pass"
    }
}

fn strategy_tool_slug(tool: &str) -> String {
    tool.chars()
        .map(|value| {
            if value.is_ascii_alphanumeric() {
                value.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn strategy_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or_default()
}

/// Recommendable tools that shell out to an external scanner, paired with the
/// binary they need. Probed here (adapter boundary) so the ranking logic only
/// sees resolved facts, never PATH.
const SCANNER_BINARY_REQUIREMENTS: &[(&str, &str)] = &[
    ("semgrep:scan", "semgrep"),
    ("codeql:scan", "codeql"),
    ("cargo-audit:scan", "cargo-audit"),
];

fn tools_missing_binaries() -> std::collections::BTreeSet<String> {
    SCANNER_BINARY_REQUIREMENTS
        .iter()
        .filter(|(_, binary)| !binary_on_path(binary))
        .map(|(tool, _)| tool.to_string())
        .collect()
}

fn binary_on_path(name: &str) -> bool {
    let Some(path_var) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path_var).any(|dir| dir.join(name).is_file())
}

fn workspace_for_input(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<WorkspaceTarget> {
    match input_target(input) {
        Some(target) => WorkspaceTarget::new(target),
        None => ctx
            .workspace
            .cloned()
            .context("module-recommender:recommend requires a workspace target"),
    }
}

fn input_target(input: &Value) -> Option<PathBuf> {
    input
        .get("target")
        .and_then(Value::as_str)
        .filter(|target| !target.trim().is_empty())
        .map(PathBuf::from)
}

fn list_findings(
    ctx: &ToolExecutionContext<'_>,
    workspace: &WorkspaceTarget,
) -> Result<(bool, Vec<Finding>)> {
    match active_findings_store(ctx, workspace) {
        Some(store) => Ok((true, recent_findings(store)?)),
        None => Ok((false, Vec::new())),
    }
}

fn active_findings_store<'ctx>(
    ctx: &'ctx ToolExecutionContext<'_>,
    workspace: &WorkspaceTarget,
) -> Option<&'ctx FindingStore> {
    let context_workspace = ctx.workspace?;
    let store = ctx.findings_store?;
    (context_workspace.root() == workspace.root()).then_some(store)
}

fn recent_findings(store: &FindingStore) -> Result<Vec<Finding>> {
    store.list_findings(50)
}

fn max_recommendations(input: &Value) -> usize {
    input
        .get("maxRecommendations")
        .and_then(Value::as_u64)
        .map(|value| value.clamp(1, 50) as usize)
        .unwrap_or(8)
}

fn recommendation_report_output(report: &RecommendationReport) -> String {
    let mut lines = vec![report.summary.clone()];
    if !report.recommendations.is_empty() {
        lines.extend(
            report
                .recommendations
                .iter()
                .take(5)
                .map(recommendation_line),
        );
    }
    lines.join("\n")
}

fn recommendation_line(recommendation: &ModuleRecommendation) -> String {
    format!(
        "  - {} ({}): {}",
        recommendation.tool,
        recommendation_priority_label(recommendation.priority),
        recommendation.reason
    )
}

fn recommendation_priority_label(priority: RecommendationPriority) -> &'static str {
    match priority {
        RecommendationPriority::High => "high",
        RecommendationPriority::Medium => "medium",
        RecommendationPriority::Low => "low",
    }
}

fn repository_signals(
    target: &Path,
    inventory: &RepositoryInventory,
    attack_surface: &AttackSurfaceMap,
    threat_model: Option<&Value>,
    findings_available: bool,
    findings: &[Finding],
) -> RepositorySignals {
    RepositorySignals {
        context_source: "deterministic-workspace-inventory".to_string(),
        attack_surface_source: "deterministic-workspace-analysis".to_string(),
        threat_model_source: threat_model_source(target, threat_model),
        findings_source: findings_source(findings_available),
        source_files: inventory.source_files.len(),
        languages: language_names(inventory),
        frameworks: framework_names(inventory),
        codeql_languages: codeql_languages(inventory),
        dependency_manifests: inventory.dependency_manifests.len(),
        config_files: inventory.config_files.len(),
        iac_files: iac_file_count(inventory),
        routes: inventory.routes_controllers.len(),
        attack_surface_total: attack_surface.summary.total,
        attack_surface_kinds: attack_surface.summary.by_kind.clone(),
        attack_surface_risk_tiers: attack_surface.summary.by_risk_tier.clone(),
        attack_surface_high_risk: attack_surface.summary.high_risk,
        attack_surface_max_risk_score: attack_surface.summary.max_risk_score,
        threat_model_present: threat_model.is_some(),
        threat_signal_count: threat_signal_count(threat_model),
        threat_model_threats: threat_model_array_count(threat_model, "threats"),
        threat_model_dfd_nodes: threat_model_dfd_count(threat_model, "nodes"),
        threat_model_dfd_flows: threat_model_dfd_count(threat_model, "flows"),
        threat_model_trust_boundaries: threat_model_dfd_count(threat_model, "trustBoundaries"),
        threat_model_related_cwes: threat_model_related_cwes(threat_model),
        findings_available,
        finding_count: findings.len(),
        high_or_critical_findings: high_or_critical_findings(findings),
        first_finding_fingerprint: first_finding_fingerprint(findings),
        first_high_finding_fingerprint: first_high_finding_fingerprint(findings),
    }
}

fn threat_model_source(target: &Path, threat_model: Option<&Value>) -> String {
    if threat_model.is_some() {
        let path = persistent_threat_model_path(target);
        path.strip_prefix(target)
            .unwrap_or(path.as_path())
            .display()
            .to_string()
    } else {
        "not-recorded".to_string()
    }
}

fn findings_source(available: bool) -> String {
    if available {
        "workspace-findings-store".to_string()
    } else {
        "unavailable".to_string()
    }
}

fn language_names(inventory: &RepositoryInventory) -> Vec<String> {
    inventory
        .languages
        .iter()
        .map(|language| language.name.clone())
        .collect()
}

fn framework_names(inventory: &RepositoryInventory) -> Vec<String> {
    inventory
        .frameworks
        .iter()
        .map(|framework| framework.name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn codeql_languages(inventory: &RepositoryInventory) -> Vec<String> {
    inventory
        .languages
        .iter()
        .filter_map(|language| codeql_language_name(&language.name))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn codeql_language_name(language: &str) -> Option<String> {
    let normalized = match language {
        "C" | "C++" => "cpp",
        "Go" => "go",
        "Java" | "Kotlin" => "java",
        "JavaScript" => "javascript",
        "Python" => "python",
        "Ruby" => "ruby",
        "Rust" => "rust",
        "TypeScript" => "typescript",
        _ => return None,
    };
    Some(normalized.to_string())
}

fn iac_file_count(inventory: &RepositoryInventory) -> usize {
    inventory
        .config_files
        .iter()
        .filter(|file| is_iac_config_kind(&file.kind))
        .count()
}

fn is_iac_config_kind(kind: &str) -> bool {
    matches!(kind, "compose" | "dockerfile")
}

fn high_or_critical_findings(findings: &[Finding]) -> usize {
    findings
        .iter()
        .filter(|finding| is_high_or_critical(finding.severity))
        .count()
}

fn first_finding_fingerprint(findings: &[Finding]) -> Option<String> {
    findings.first().map(|finding| finding.fingerprint.clone())
}

fn first_high_finding_fingerprint(findings: &[Finding]) -> Option<String> {
    findings
        .iter()
        .find(|finding| is_high_or_critical(finding.severity))
        .map(|finding| finding.fingerprint.clone())
}

fn is_high_or_critical(severity: Severity) -> bool {
    matches!(severity, Severity::Critical | Severity::High)
}

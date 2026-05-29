use super::threat_model_signals::{
    threat_model_array_count, threat_model_dfd_count, threat_model_related_cwes,
    threat_signal_count,
};
use super::*;

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
    let summary = report.summary.clone();
    let output = recommendation_report_output(&report);
    let data = serde_json::to_value(report).context("Could not serialize module recommendations")?;
    Ok(crate::module_result::completed_output_result(
        summary, output, data,
    ))
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
        lines.extend(report.recommendations.iter().take(5).map(recommendation_line));
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

use super::component_classify::component_recommendations;
use super::threat_model_signals::{
    threat_model_array_count, threat_model_dfd_count, threat_model_related_cwes,
    threat_signal_count,
};
use super::*;
use crate::fs_atomic::{now_ms, slug};
use crate::strategy::{
    acquire_recovered_strategy_lock, apply_strategy_corrections_unlocked,
    load_strategy_queue_unlocked, save_strategy_queue_unlocked, StrategyPhase, StrategyPreflight,
    StrategyPreflightStatus, StrategyProposal, StrategyProposalStatus, StrategyResourceRisk,
};

pub(crate) fn execute_module_recommender_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    available_tools: Vec<String>,
) -> Result<Value> {
    let workspace = workspace_for_input(&input, ctx)?;
    let snapshot = crate::workspace::source_snapshot::SourceSnapshot::capture(
        ctx,
        "module-recommender:recommend",
        workspace.root(),
    )?;
    let ranking = ModelRanking::resolve(ctx, runtime, &input, workspace.root())?;
    let (request, coverage) =
        inspect_recommendation_facts(&input, &workspace, available_tools, ctx)?;
    let report = build_recommendation_report_ranked(request, ranking)?;
    snapshot.ensure_current(ctx, "module-recommender:recommend", workspace.root())?;
    let strategy_proposals = persist_strategy_proposals(&workspace, &report, ctx.run_id())?;
    write_strategy_run_artifact(ctx, &strategy_proposals)?;
    let summary = report.summary.clone();
    let output = recommendation_report_output(&report);
    let data =
        serde_json::to_value(report).context("Could not serialize module recommendations")?;
    Ok(snapshot.attach(super::inventory_coverage::output(
        summary, output, data, coverage,
    )))
}

fn inspect_recommendation_facts(
    input: &Value,
    workspace: &WorkspaceTarget,
    available_tools: Vec<String>,
    ctx: &ToolExecutionContext<'_>,
) -> Result<(RecommenderRequest, Value)> {
    let inventory = crate::repository_inventory::build_repository_inventory_with_observer(
        workspace.root(),
        &mut |_| {},
        &|| ctx.ensure_active().is_err(),
    )?;
    ctx.ensure_active()?;
    let attack_surface = build_attack_surface_map_from_inventory(workspace.root(), &inventory)?;
    let (findings_available, findings) = list_findings(ctx, &workspace)?;
    let request = recommender_request(
        input,
        workspace,
        available_tools,
        &inventory,
        &attack_surface,
        findings_available,
        &findings,
    )?;
    Ok((request, super::inventory_coverage::receipt(&inventory)))
}

fn recommender_request(
    input: &Value,
    workspace: &WorkspaceTarget,
    available_tools: Vec<String>,
    inventory: &RepositoryInventory,
    attack_surface: &AttackSurfaceMap,
    findings_available: bool,
    findings: &[Finding],
) -> Result<RecommenderRequest> {
    let threat_model = try_load_persistent_threat_model(workspace.root())?;
    Ok(RecommenderRequest {
        target: workspace.root().display().to_string(),
        max_recommendations: max_recommendations(input)?,
        available_tools: available_tools.into_iter().collect(),
        tools_missing_binaries: tools_missing_binaries(),
        signals: repository_signals(
            workspace.root(),
            inventory,
            attack_surface,
            threat_model.as_ref(),
            findings_available,
            findings,
        ),
        components: component_recommendations(
            workspace.root(),
            &recommender_scope_tree(workspace.root())?,
            inventory,
            attack_surface,
        ),
    })
}

fn recommender_scope_tree(root: &Path) -> Result<crate::workspace::NestedProjectScopeTree> {
    match crate::workspace::load_nested_project_scopes(root) {
        Ok(Some(tree)) => Ok(tree),
        Ok(None) => Ok(crate::workspace::discover_nested_project_scopes(root)),
        Err(error) => Err(error).context("Could not load persisted project scopes"),
    }
}

fn persist_strategy_proposals(
    workspace: &WorkspaceTarget,
    report: &RecommendationReport,
    run_id: Option<String>,
) -> Result<Vec<StrategyProposal>> {
    let _guard = acquire_recovered_strategy_lock(workspace)?;
    let mut existing = load_strategy_queue_unlocked(workspace)?;
    let now = now_ms();
    let mut generated_ids = Vec::new();
    let mut generated = Vec::new();
    for recommendation in &report.recommendations {
        let proposal = strategy_proposal_from_recommendation(recommendation, run_id.clone(), now);
        generated.push(proposal);
    }
    apply_strategy_corrections_unlocked(workspace, run_id.as_deref(), &mut generated)?;
    for proposal in generated {
        generated_ids.push(super::proposal_history::retain_draft(
            &mut existing,
            proposal,
        )?);
    }
    save_strategy_queue_unlocked(workspace, &existing)?;
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
        yield_score: None,
        estimated_rounds: None,
        approved_cost_usd: None,
        actual_cost_usd: None,
        findings_count: None,
        confirmed_count: None,
        result_run_id: None,
        failure: None,
        preflight: strategy_preflight(recommendation, blocked),
        resource_risk: strategy_resource_risk(recommendation, blocked),
        status: StrategyProposalStatus::Proposed,
        source_run_id: run_id,
        tool: Some(recommendation.tool.clone()),
        next_input: Some(recommendation.next_input.clone()),
        scope_proposal_ref: None,
        created_at_ms: now,
        updated_at_ms: now,
    }
}

fn strategy_preflight(recommendation: &ModuleRecommendation, blocked: bool) -> StrategyPreflight {
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
    slug(tool, "tool", usize::MAX)
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
        None => {
            ctx.workspace
                .cloned()
                .context(crate::workspace::active_workspace_required_message(
                    "module-recommender:recommend",
                ))
        }
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

fn max_recommendations(input: &Value) -> Result<usize> {
    let count = input
        .get("maxRecommendations")
        .map(|value| {
            value
                .as_u64()
                .context("maxRecommendations must be a positive integer")
        })
        .transpose()?
        .unwrap_or(8);
    anyhow::ensure!(
        (1..=50).contains(&count),
        "maxRecommendations must be between 1 and 50"
    );
    Ok(count as usize)
}

fn recommendation_report_output(report: &RecommendationReport) -> String {
    let mut lines = vec![report.summary.clone(), format!("Ranking: {}. Suggestions require a separately approved plan; no discovery jobs were started.", report.ranking_mode)];
    if !report.components.is_empty() {
        lines.extend(report.components.iter().take(3).map(component_line));
    }
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

fn component_line(component: &ComponentRecommendation) -> String {
    format!(
        "  - component {} ({}, {}): {}",
        component.rel_path,
        component.class.label(),
        component_tier_label(component.tier),
        component
            .reasons
            .first()
            .cloned()
            .unwrap_or_else(|| "scoped scan candidate".to_string())
    )
}

fn recommendation_line(recommendation: &ModuleRecommendation) -> String {
    format!(
        "  - {} ({}): {}",
        recommendation.tool,
        recommendation_priority_label(recommendation.priority),
        recommendation.reason
    )
}

fn component_tier_label(tier: ComponentTier) -> &'static str {
    match tier {
        ComponentTier::High => "high",
        ComponentTier::Medium => "medium",
        ComponentTier::Low => "low",
    }
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
    let mut signals = inventory_repository_signals(target, inventory, attack_surface);
    apply_threat_model_signals(&mut signals, target, threat_model);
    apply_finding_signals(&mut signals, findings_available, findings);
    signals
}

fn inventory_repository_signals(
    target: &Path,
    inventory: &RepositoryInventory,
    attack_surface: &AttackSurfaceMap,
) -> RepositorySignals {
    let boundary_labels = product_boundary_labels(target);
    RepositorySignals {
        context_source: "deterministic-workspace-inventory".to_string(),
        attack_surface_source: "deterministic-workspace-analysis".to_string(),
        source_files: inventory.source_files.len(),
        languages: language_names(inventory),
        frameworks: framework_names(inventory),
        product_boundaries: boundary_labels.len(),
        product_boundary_labels: boundary_labels,
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
        ..RepositorySignals::default()
    }
}

fn apply_threat_model_signals(
    signals: &mut RepositorySignals,
    target: &Path,
    threat_model: Option<&Value>,
) {
    signals.threat_model_source = threat_model_source(target, threat_model);
    signals.threat_model_present = threat_model.is_some();
    signals.threat_signal_count = threat_signal_count(threat_model);
    signals.threat_model_threats = threat_model_array_count(threat_model, "threats");
    signals.threat_model_dfd_nodes = threat_model_dfd_count(threat_model, "nodes");
    signals.threat_model_dfd_flows = threat_model_dfd_count(threat_model, "flows");
    signals.threat_model_trust_boundaries = threat_model_dfd_count(threat_model, "trustBoundaries");
    signals.threat_model_related_cwes = threat_model_related_cwes(threat_model);
}

fn apply_finding_signals(
    signals: &mut RepositorySignals,
    findings_available: bool,
    findings: &[Finding],
) {
    signals.findings_source = findings_source(findings_available);
    signals.findings_available = findings_available;
    signals.finding_count = findings.len();
    signals.high_or_critical_findings = high_or_critical_findings(findings);
    signals.first_finding_fingerprint = first_finding_fingerprint(findings);
    signals.first_high_finding_fingerprint = first_high_finding_fingerprint(findings);
}

fn product_boundary_labels(target: &Path) -> Vec<String> {
    let tree = match crate::workspace::load_nested_project_scopes(target) {
        Ok(Some(tree)) => tree,
        _ => crate::workspace::discover_nested_project_scopes(target),
    };
    tree.non_root_scopes()
        .filter(|scope| {
            matches!(
                scope.kind,
                crate::workspace::NestedProjectKind::PackageRoot
                    | crate::workspace::NestedProjectKind::Submodule
                    | crate::workspace::NestedProjectKind::EntrypointCluster
            )
        })
        .map(|scope| scope.display_label())
        .collect()
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

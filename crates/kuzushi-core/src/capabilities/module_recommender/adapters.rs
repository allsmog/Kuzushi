use super::*;

pub(crate) fn execute_module_recommender_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
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
            &inventory,
            &attack_surface,
            threat_model.as_ref(),
            findings_available,
            &findings,
        ),
    };
    serde_json::to_value(build_recommendation_report(request))
        .context("Could not serialize module recommendations")
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

fn repository_signals(
    inventory: &RepositoryInventory,
    attack_surface: &AttackSurfaceMap,
    threat_model: Option<&Value>,
    findings_available: bool,
    findings: &[Finding],
) -> RepositorySignals {
    RepositorySignals {
        context_source: "deterministic-workspace-inventory".to_string(),
        attack_surface_source: "deterministic-workspace-analysis".to_string(),
        threat_model_source: threat_model_source(threat_model),
        findings_source: findings_source(findings_available),
        source_files: inventory.source_files.len(),
        languages: language_names(inventory),
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
        findings_available,
        finding_count: findings.len(),
        high_or_critical_findings: high_or_critical_findings(findings),
        first_finding_fingerprint: first_finding_fingerprint(findings),
        first_high_finding_fingerprint: first_high_finding_fingerprint(findings),
    }
}

fn threat_model_source(threat_model: Option<&Value>) -> String {
    if threat_model.is_some() {
        ".kuzushi/threat-model.json".to_string()
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

fn threat_signal_count(threat_model: Option<&Value>) -> usize {
    threat_model
        .map(canonical_threat_document)
        .map(count_threat_model_signals)
        .unwrap_or(0)
}

fn count_threat_model_signals(document: &Value) -> usize {
    count_known_arrays(document) + count_nested_known_arrays(document)
}

fn count_nested_known_arrays(document: &Value) -> usize {
    ["dfd", "model", "threatModel"]
        .iter()
        .filter_map(|key| document.get(*key))
        .map(count_known_arrays)
        .sum()
}

fn count_known_arrays(document: &Value) -> usize {
    threat_signal_keys()
        .iter()
        .map(|key| json_array_len(document, key))
        .sum()
}

fn threat_signal_keys() -> &'static [&'static str] {
    &[
        "actors",
        "edges",
        "findings",
        "nodes",
        "scenarios",
        "securityStories",
        "stories",
        "threats",
    ]
}

fn json_array_len(document: &Value, key: &str) -> usize {
    document
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0)
}

fn threat_model_dfd_count(threat_model: Option<&Value>, key: &str) -> usize {
    let Some(document) = threat_model.map(canonical_threat_document) else {
        return 0;
    };
    document
        .get("dfd")
        .and_then(|dfd| dfd.get(key))
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0)
}

fn threat_model_array_count(threat_model: Option<&Value>, key: &str) -> usize {
    threat_model
        .map(canonical_threat_document)
        .map(|document| json_array_len(document, key))
        .unwrap_or(0)
}

fn canonical_threat_document(value: &Value) -> &Value {
    value.get("document").unwrap_or(value)
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

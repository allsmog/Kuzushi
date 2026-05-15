use super::*;

pub(super) fn recommendation_rules() -> &'static [RecommendationRule] {
    RECOMMENDATION_RULES
}

static RECOMMENDATION_RULES: &[RecommendationRule] = &[
    RecommendationRule {
        tool: "secret-scan:scan",
        priority: RecommendationPriority::High,
        reason:
            "Scan source and config files for high-confidence credentials before deeper analysis.",
        condition: has_source_files,
        signals: source_file_signals,
        next_input: target_input,
    },
    RecommendationRule {
        tool: "dep-hygiene:check",
        priority: RecommendationPriority::High,
        reason: "Dependency manifests are present and should be checked deterministically.",
        condition: has_dependency_manifests,
        signals: dependency_signals,
        next_input: target_input,
    },
    RecommendationRule {
        tool: "iac-scan:scan",
        priority: RecommendationPriority::High,
        reason: "Infrastructure or container configuration is present.",
        condition: has_iac_files,
        signals: iac_signals,
        next_input: target_input,
    },
    RecommendationRule {
        tool: "semgrep:scan",
        priority: RecommendationPriority::High,
        reason: "Source files are present and match the fast native SAST path.",
        condition: has_source_files,
        signals: source_file_signals,
        next_input: target_input,
    },
    RecommendationRule {
        tool: "codeql:scan",
        priority: RecommendationPriority::Medium,
        reason: "Detected languages have CodeQL coverage for deeper semantic queries.",
        condition: has_codeql_languages,
        signals: codeql_signals,
        next_input: codeql_input,
    },
    RecommendationRule {
        tool: "threat-model:build",
        priority: RecommendationPriority::Medium,
        reason: "Attack-surface signals exist but no persisted threat model was found.",
        condition: needs_threat_model,
        signals: attack_surface_signals,
        next_input: target_input,
    },
    RecommendationRule {
        tool: "triage:run",
        priority: RecommendationPriority::Medium,
        reason: "Persisted findings are available for model-backed triage.",
        condition: has_findings,
        signals: finding_signals,
        next_input: triage_input,
    },
    RecommendationRule {
        tool: "verify:finding",
        priority: RecommendationPriority::Low,
        reason: "A high-severity finding is available for focused exploitability verification.",
        condition: has_high_finding,
        signals: high_finding_signals,
        next_input: verify_input,
    },
    RecommendationRule {
        tool: "context:build",
        priority: RecommendationPriority::Low,
        reason: "Refresh the deterministic context snapshot before long-running analysis.",
        condition: always,
        signals: context_signals,
        next_input: target_input,
    },
];

fn always(_: &RepositorySignals) -> bool {
    true
}

fn has_source_files(signals: &RepositorySignals) -> bool {
    signals.source_files > 0
}

fn has_dependency_manifests(signals: &RepositorySignals) -> bool {
    signals.dependency_manifests > 0
}

fn has_iac_files(signals: &RepositorySignals) -> bool {
    signals.iac_files > 0
}

fn has_codeql_languages(signals: &RepositorySignals) -> bool {
    !signals.codeql_languages.is_empty()
}

fn needs_threat_model(signals: &RepositorySignals) -> bool {
    signals.attack_surface_total > 0 && !signals.threat_model_present
}

fn has_findings(signals: &RepositorySignals) -> bool {
    signals.finding_count > 0
}

fn has_high_finding(signals: &RepositorySignals) -> bool {
    signals.first_high_finding_fingerprint.is_some()
}

fn target_input(request: &RecommenderRequest) -> Value {
    json!({ "target": request.target })
}

fn triage_input(_: &RecommenderRequest) -> Value {
    json!({ "batchSize": 20 })
}

fn verify_input(request: &RecommenderRequest) -> Value {
    json!({ "fingerprint": request.signals.first_high_finding_fingerprint })
}

fn codeql_input(request: &RecommenderRequest) -> Value {
    match request.signals.codeql_languages.as_slice() {
        [language] => json!({ "target": request.target, "language": language }),
        _ => json!({ "target": request.target, "multiLanguage": true }),
    }
}

fn context_signals(signals: &RepositorySignals) -> Vec<String> {
    vec![format!("{} indexed source file(s)", signals.source_files)]
}

fn source_file_signals(signals: &RepositorySignals) -> Vec<String> {
    vec![format!("{} source file(s)", signals.source_files)]
}

fn dependency_signals(signals: &RepositorySignals) -> Vec<String> {
    vec![format!(
        "{} dependency manifest(s)",
        signals.dependency_manifests
    )]
}

fn iac_signals(signals: &RepositorySignals) -> Vec<String> {
    vec![format!("{} IaC/config file(s)", signals.iac_files)]
}

fn codeql_signals(signals: &RepositorySignals) -> Vec<String> {
    vec![format!(
        "CodeQL languages: {}",
        signals.codeql_languages.join(", ")
    )]
}

fn attack_surface_signals(signals: &RepositorySignals) -> Vec<String> {
    let mut surface_signals = vec![format!(
        "{} attack-surface boundary/boundaries",
        signals.attack_surface_total
    )];
    if signals.attack_surface_high_risk > 0 {
        surface_signals.push(format!(
            "{} high/critical attack-surface boundary/boundaries",
            signals.attack_surface_high_risk
        ));
    }
    if signals.attack_surface_max_risk_score > 0 {
        surface_signals.push(format!(
            "max attack-surface risk score {}",
            signals.attack_surface_max_risk_score
        ));
    }
    if let Some(tiers) = attack_surface_tier_signal(signals) {
        surface_signals.push(tiers);
    }
    surface_signals
}

fn attack_surface_tier_signal(signals: &RepositorySignals) -> Option<String> {
    if signals.attack_surface_risk_tiers.is_empty() {
        return None;
    }
    let tiers = ["critical", "high", "medium", "low"]
        .into_iter()
        .filter_map(|tier| tier_count_signal(tier, &signals.attack_surface_risk_tiers))
        .collect::<Vec<_>>();
    (!tiers.is_empty()).then(|| format!("attack-surface risk tiers: {}", tiers.join(", ")))
}

fn tier_count_signal(tier: &str, counts: &BTreeMap<String, usize>) -> Option<String> {
    counts
        .get(tier)
        .copied()
        .filter(|count| *count > 0)
        .map(|count| format!("{tier}={count}"))
}

fn finding_signals(signals: &RepositorySignals) -> Vec<String> {
    vec![format!("{} persisted finding(s)", signals.finding_count)]
}

fn high_finding_signals(signals: &RepositorySignals) -> Vec<String> {
    vec![format!(
        "{} high/critical finding(s)",
        signals.high_or_critical_findings
    )]
}

use super::*;

#[derive(Debug, Clone)]
pub(crate) struct RecommenderRequest {
    pub(crate) target: String,
    pub(crate) max_recommendations: usize,
    pub(crate) available_tools: BTreeSet<String>,
    pub(crate) signals: RepositorySignals,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecommendationReport {
    pub(crate) ok: bool,
    pub(crate) summary: String,
    pub(crate) target: String,
    pub(crate) signals: RepositorySignals,
    pub(crate) capabilities: CapabilitySummary,
    pub(crate) recommendations: Vec<ModuleRecommendation>,
    pub(crate) warnings: Vec<String>,
    pub(crate) errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RepositorySignals {
    pub(crate) context_source: String,
    pub(crate) attack_surface_source: String,
    pub(crate) threat_model_source: String,
    pub(crate) findings_source: String,
    pub(crate) source_files: usize,
    pub(crate) languages: Vec<String>,
    pub(crate) frameworks: Vec<String>,
    pub(crate) codeql_languages: Vec<String>,
    pub(crate) dependency_manifests: usize,
    pub(crate) config_files: usize,
    pub(crate) iac_files: usize,
    pub(crate) routes: usize,
    pub(crate) attack_surface_total: usize,
    pub(crate) attack_surface_kinds: BTreeMap<String, usize>,
    pub(crate) attack_surface_risk_tiers: BTreeMap<String, usize>,
    pub(crate) attack_surface_high_risk: usize,
    pub(crate) attack_surface_max_risk_score: u16,
    pub(crate) threat_model_present: bool,
    pub(crate) threat_signal_count: usize,
    pub(crate) threat_model_threats: usize,
    pub(crate) threat_model_dfd_nodes: usize,
    pub(crate) threat_model_dfd_flows: usize,
    pub(crate) threat_model_trust_boundaries: usize,
    pub(crate) threat_model_related_cwes: BTreeMap<String, usize>,
    pub(crate) findings_available: bool,
    pub(crate) finding_count: usize,
    pub(crate) high_or_critical_findings: usize,
    pub(crate) first_finding_fingerprint: Option<String>,
    pub(crate) first_high_finding_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CapabilitySummary {
    pub(crate) available_tool_count: usize,
    pub(crate) recommended_tool_count: usize,
    pub(crate) skipped_missing_tools: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ModuleRecommendation {
    pub(crate) module_id: String,
    pub(crate) tool: String,
    pub(crate) priority: RecommendationPriority,
    pub(crate) reason: String,
    pub(crate) signals: Vec<String>,
    pub(crate) requires_runtime: bool,
    pub(crate) next_input: Value,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RecommendationPriority {
    High,
    Medium,
    Low,
}

impl RecommendationPriority {
    pub(crate) fn sort_key(self) -> u8 {
        match self {
            Self::High => 0,
            Self::Medium => 1,
            Self::Low => 2,
        }
    }
}

pub(crate) struct RecommendationRule {
    pub(crate) tool: &'static str,
    pub(crate) priority: RecommendationPriority,
    pub(crate) reason: &'static str,
    pub(crate) condition: fn(&RepositorySignals) -> bool,
    pub(crate) signals: fn(&RepositorySignals) -> Vec<String>,
    pub(crate) next_input: fn(&RecommenderRequest) -> Value,
}

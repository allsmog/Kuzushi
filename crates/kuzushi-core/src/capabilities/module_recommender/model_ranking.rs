//! Optional session-model ranking for the recommender. When a model is
//! configured and a runtime is available, the model picks/prioritizes from the
//! *available* tools given the target's signals; its output is checked
//! against the available set (hallucinated tools are dropped). On any failure
//! — no model, query error, unparseable output, empty result — the caller
//! falls back to the deterministic rule catalog. No silent model fallback:
//! the model is `ctx.toolModel ?? ctx.config.model`, never a baked-in default.

use super::*;
use crate::runtime::{resolve_explicit_model, AgentQueryRequest, AgentRuntime};

const RECOMMENDER_SYSTEM_PROMPT: &str =
    "You are a security-tooling planner for the Kuzushi agent. \
Given a target's signals and the list of AVAILABLE tools, choose the tools most worth running and \
rank them. Only choose tools from the AVAILABLE list. Reply with ONLY a JSON array of objects: \
[{\"tool\":\"<module:action>\",\"priority\":\"high|medium|low\",\"reason\":\"<one sentence>\"}]. \
No prose, no code fences.";

pub(crate) struct ModelRanking<'a> {
    runtime: Option<&'a dyn AgentRuntime>,
    model: Option<String>,
    unavailable_reason: Option<String>,
    cwd: PathBuf,
}

pub(crate) struct ModelRankingOutcome {
    pub(crate) recommendations: Option<Vec<ModuleRecommendation>>,
    pub(crate) model: Option<String>,
    pub(crate) cost: crate::runtime::RuntimeCostReport,
    pub(crate) provider_spend_unresolved: bool,
    pub(crate) fallback_reason: Option<String>,
}

impl<'a> ModelRanking<'a> {
    pub(crate) fn resolve(
        ctx: &ToolExecutionContext<'_>,
        runtime: Option<&'a dyn AgentRuntime>,
        input: &Value,
        root: &Path,
    ) -> Self {
        if !model_ranking_enabled(input) {
            return Self {
                runtime: None,
                model: None,
                unavailable_reason: Some("model ranking was disabled by tool input".to_string()),
                cwd: root.to_path_buf(),
            };
        }
        let input_model = input
            .get("model")
            .and_then(Value::as_str)
            .map(str::to_string);
        let resolved = resolve_explicit_model(
            "module-recommender:recommend",
            input_model,
            ctx.config.model.as_deref(),
        );
        let (model, unavailable_reason) = match resolved {
            Ok(model) => (Some(model), None),
            Err(error) => (None, Some(error.to_string())),
        };
        Self {
            runtime,
            model,
            unavailable_reason,
            cwd: root.to_path_buf(),
        }
    }

    pub(crate) fn rank(&self, request: &RecommenderRequest) -> ModelRankingOutcome {
        let Some(runtime) = self.runtime else {
            return self.unattempted_fallback("agent runtime is unavailable");
        };
        let Some(model) = self.model.as_ref() else {
            return self.unattempted_fallback("no explicit model is available");
        };
        let query = AgentQueryRequest::new(
            model.clone(),
            self.cwd.clone(),
            RECOMMENDER_SYSTEM_PROMPT,
            render_recommender_prompt(request),
        );
        let response = match crate::runtime::query_blocking_checked(runtime, query) {
            Ok(response) => response,
            Err(error) => return self.failed_query(model, error),
        };
        let cost = match response.checked_cost_report() {
            Ok(cost) => cost,
            Err(error) => return self.failed_query(model, error),
        };
        let Some(picks) = parse_tool_picks(&response.text) else {
            return fallback_after_response(model, cost, "model response was not a JSON pick list");
        };
        let recommendations = build_model_recommendations(&picks, request);
        if recommendations.is_empty() {
            return fallback_after_response(
                model,
                cost,
                "model response contained no available tool picks",
            );
        }
        ModelRankingOutcome {
            recommendations: Some(recommendations),
            model: Some(model.clone()),
            cost,
            provider_spend_unresolved: !cost.is_complete(),
            fallback_reason: None,
        }
    }

    fn unattempted_fallback(&self, default_reason: &str) -> ModelRankingOutcome {
        ModelRankingOutcome {
            recommendations: None,
            model: self.model.clone(),
            cost: exact_zero_cost(),
            provider_spend_unresolved: false,
            fallback_reason: Some(
                self.unavailable_reason
                    .clone()
                    .unwrap_or_else(|| default_reason.to_string()),
            ),
        }
    }

    fn failed_query(&self, model: &str, error: anyhow::Error) -> ModelRankingOutcome {
        ModelRankingOutcome {
            recommendations: None,
            model: Some(model.to_string()),
            cost: crate::runtime::RuntimeCostReport::INCOMPLETE_ZERO,
            provider_spend_unresolved: true,
            fallback_reason: Some(format!("model ranking query failed: {error}")),
        }
    }
}

fn fallback_after_response(
    model: &str,
    cost: crate::runtime::RuntimeCostReport,
    reason: &str,
) -> ModelRankingOutcome {
    ModelRankingOutcome {
        recommendations: None,
        model: Some(model.to_string()),
        cost,
        provider_spend_unresolved: !cost.is_complete(),
        fallback_reason: Some(reason.to_string()),
    }
}

fn exact_zero_cost() -> crate::runtime::RuntimeCostReport {
    crate::runtime::RuntimeCostReport::known(crate::runtime::RuntimeCost::ZERO)
}

pub(crate) fn model_ranking_enabled(input: &Value) -> bool {
    input
        .get("useModelRanking")
        .and_then(Value::as_bool)
        .unwrap_or(true)
}

fn render_recommender_prompt(request: &RecommenderRequest) -> String {
    let signals = &request.signals;
    let mut available: Vec<&str> = request.available_tools.iter().map(String::as_str).collect();
    available.sort_unstable();
    format!(
        "TARGET: {target}\nSIGNALS:\n  source files: {files}\n  languages: {langs}\n  frameworks: {fw}\n  \
product boundaries: {boundaries}\n  \
attack-surface entries: {surface} ({high} high-risk)\n  threat model present: {tm}\n  findings: {findings}\n\n\
AVAILABLE tools ({count}):\n{tools}\n\nPick up to {max} tools to run next, highest-value first.",
        target = request.target,
        files = signals.source_files,
        langs = join_or_none(&signals.languages),
        fw = join_or_none(&signals.frameworks),
        boundaries = join_or_none(&signals.product_boundary_labels),
        surface = signals.attack_surface_total,
        high = signals.attack_surface_high_risk,
        tm = signals.threat_model_present,
        findings = signals.finding_count,
        count = available.len(),
        tools = available.join(", "),
        max = request.max_recommendations,
    )
}

fn join_or_none(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(", ")
    }
}

#[derive(serde::Deserialize)]
struct ModelPick {
    tool: String,
    #[serde(default)]
    priority: String,
    #[serde(default)]
    reason: String,
}

/// Pull the JSON array out of the model's reply, tolerating leading/trailing
/// prose or code fences.
fn parse_tool_picks(text: &str) -> Option<Vec<ModelPick>> {
    let start = text.find('[')?;
    let end = text.rfind(']')?;
    if end < start {
        return None;
    }
    serde_json::from_str::<Vec<ModelPick>>(&text[start..=end]).ok()
}

fn build_model_recommendations(
    picks: &[ModelPick],
    request: &RecommenderRequest,
) -> Vec<ModuleRecommendation> {
    let mut seen = BTreeSet::new();
    picks
        .iter()
        .filter(|pick| request.available_tools.contains(&pick.tool))
        .filter(|pick| seen.insert(pick.tool.clone()))
        .take(request.max_recommendations)
        .map(model_recommendation)
        .collect()
}

fn model_recommendation(pick: &ModelPick) -> ModuleRecommendation {
    let reason = if pick.reason.trim().is_empty() {
        "session model recommended this tool for the target".to_string()
    } else {
        pick.reason.clone()
    };
    ModuleRecommendation {
        module_id: pick
            .tool
            .split_once(':')
            .map(|(module, _)| module)
            .unwrap_or(&pick.tool)
            .to_string(),
        tool: pick.tool.clone(),
        priority: priority_from_str(&pick.priority),
        reason,
        signals: vec!["model-ranked".to_string()],
        requires_runtime: crate::modules::tool_needs_runtime(&pick.tool, &json!({})),
        next_input: json!({}),
    }
}

fn priority_from_str(value: &str) -> RecommendationPriority {
    match value.trim().to_ascii_lowercase().as_str() {
        "high" | "critical" => RecommendationPriority::High,
        "low" => RecommendationPriority::Low,
        _ => RecommendationPriority::Medium,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::TriageOutcome;
    use crate::runtime::{AgentQueryResponse, TriageRequest};

    fn request(tools: &[&str]) -> RecommenderRequest {
        RecommenderRequest {
            target: "/tmp/t".to_string(),
            max_recommendations: 5,
            tools_missing_binaries: Default::default(),
            available_tools: tools.iter().map(|t| t.to_string()).collect(),
            signals: signals_stub(),
            components: Vec::new(),
        }
    }

    fn signals_stub() -> RepositorySignals {
        RepositorySignals {
            context_source: String::new(),
            attack_surface_source: String::new(),
            threat_model_source: String::new(),
            findings_source: String::new(),
            source_files: 0,
            languages: Vec::new(),
            frameworks: Vec::new(),
            product_boundaries: 0,
            product_boundary_labels: Vec::new(),
            codeql_languages: Vec::new(),
            dependency_manifests: 0,
            config_files: 0,
            iac_files: 0,
            routes: 0,
            attack_surface_total: 0,
            attack_surface_kinds: BTreeMap::new(),
            attack_surface_risk_tiers: BTreeMap::new(),
            attack_surface_high_risk: 0,
            attack_surface_max_risk_score: 0,
            threat_model_present: false,
            threat_signal_count: 0,
            threat_model_threats: 0,
            threat_model_dfd_nodes: 0,
            threat_model_dfd_flows: 0,
            threat_model_trust_boundaries: 0,
            threat_model_related_cwes: BTreeMap::new(),
            findings_available: false,
            finding_count: 0,
            high_or_critical_findings: 0,
            first_finding_fingerprint: None,
            first_high_finding_fingerprint: None,
        }
    }

    #[test]
    fn parse_tool_picks_tolerates_prose_and_fences() {
        let text = "Sure! ```json\n[{\"tool\":\"semgrep:scan\",\"priority\":\"high\",\"reason\":\"src\"}]\n``` done";
        let picks = parse_tool_picks(text).expect("array");
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].tool, "semgrep:scan");
    }

    #[test]
    fn build_drops_hallucinated_tools_and_dedups() {
        let picks = vec![
            ModelPick {
                tool: "semgrep:scan".into(),
                priority: "high".into(),
                reason: "x".into(),
            },
            ModelPick {
                tool: "not-a-real:tool".into(),
                priority: "".into(),
                reason: "".into(),
            },
            ModelPick {
                tool: "semgrep:scan".into(),
                priority: "low".into(),
                reason: "dup".into(),
            },
        ];
        let recs = build_model_recommendations(&picks, &request(&["semgrep:scan", "triage:run"]));
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].tool, "semgrep:scan");
        assert_eq!(recs[0].priority, RecommendationPriority::High);
        assert_eq!(recs[0].signals, vec!["model-ranked".to_string()]);
    }

    struct RankingRuntime {
        response: Option<AgentQueryResponse>,
    }

    impl AgentRuntime for RankingRuntime {
        fn query_blocking(&self, _request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            self.response
                .clone()
                .context("scripted module-ranking query failure")
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            anyhow::bail!("unused")
        }
    }

    #[test]
    fn ranking_success_preserves_exact_provider_cost() {
        let runtime = ranking_runtime(
            r#"[{"tool":"semgrep:scan","priority":"high","reason":"best signal"}]"#,
            0.4,
            true,
        );
        let config = ranking_config();
        let ctx = ranking_context(&config);
        let ranking = ModelRanking::resolve(&ctx, Some(&runtime), &json!({}), Path::new("/tmp"));

        let outcome = ranking.rank(&request(&["semgrep:scan"]));

        assert_eq!(outcome.recommendations.unwrap().len(), 1);
        assert_eq!(outcome.cost.exact_usd(), Some(0.4));
        assert!(!outcome.provider_spend_unresolved);
        assert!(outcome.fallback_reason.is_none());
    }

    #[test]
    fn query_failure_marks_provider_spend_unresolved() {
        let runtime = RankingRuntime { response: None };
        let config = ranking_config();
        let ctx = ranking_context(&config);
        let ranking = ModelRanking::resolve(&ctx, Some(&runtime), &json!({}), Path::new("/tmp"));

        let outcome = ranking.rank(&request(&["semgrep:scan"]));

        assert!(outcome.recommendations.is_none());
        assert_eq!(outcome.cost.exact_usd(), None);
        assert_eq!(outcome.cost.observed_usd(), 0.0);
        assert!(outcome.provider_spend_unresolved);
        assert!(outcome
            .fallback_reason
            .unwrap()
            .contains("scripted module-ranking query failure"));
    }

    #[test]
    fn parse_fallback_keeps_the_reported_cost_exact() {
        let runtime = ranking_runtime("not JSON", 0.2, true);
        let config = ranking_config();
        let ctx = ranking_context(&config);
        let ranking = ModelRanking::resolve(&ctx, Some(&runtime), &json!({}), Path::new("/tmp"));

        let outcome = ranking.rank(&request(&["semgrep:scan"]));

        assert!(outcome.recommendations.is_none());
        assert_eq!(outcome.cost.exact_usd(), Some(0.2));
        assert!(!outcome.provider_spend_unresolved);
        assert!(outcome.fallback_reason.is_some());
    }

    fn ranking_runtime(text: &str, cost_usd: f64, reported: bool) -> RankingRuntime {
        RankingRuntime {
            response: Some(AgentQueryResponse {
                text: text.to_string(),
                cost_usd,
                cost_usd_reported: reported,
                ..AgentQueryResponse::default()
            }),
        }
    }

    fn ranking_config() -> crate::config::V2Config {
        crate::config::V2Config {
            model: Some("openai:test".to_string()),
            ..Default::default()
        }
    }

    fn ranking_context(config: &crate::config::V2Config) -> ToolExecutionContext<'_> {
        ToolExecutionContext {
            config,
            workspace: None,
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        }
    }

    #[test]
    fn priority_parsing_defaults_to_medium() {
        assert_eq!(priority_from_str("HIGH"), RecommendationPriority::High);
        assert_eq!(priority_from_str("low"), RecommendationPriority::Low);
        assert_eq!(priority_from_str("weird"), RecommendationPriority::Medium);
    }

    #[test]
    fn use_model_ranking_flag_can_disable_model_path() {
        assert!(model_ranking_enabled(&json!({})));
        assert!(!model_ranking_enabled(&json!({ "useModelRanking": false })));
    }
}

//! Per-role model routing.
//!
//! The router maps a logical agent role (e.g. "deep auditor") to one concrete
//! `provider:model` string. It deliberately does not rotate to alternate
//! providers or models on failure; Kuzushi's runtime policy requires explicit
//! operator consent for any model change.
//!
//! Routing is loaded from `~/.kuzushi/models.toml` (and an optional
//! `<target>/.kuzushi/models.toml` for project-local overrides). The
//! schema is intentionally narrow — operators edit a few lines, not a full
//! Cargo-shaped config:
//!
//! ```toml
//! default_model = "anthropic:claude-sonnet-4-6"
//!
//! [roles.classifier_gate]
//! primary = "anthropic:claude-haiku-4-5"
//!
//! [roles.deep_auditor]
//! primary = "anthropic:claude-opus-4-7"
//!
//! [concurrency]                # consumed in a later phase; loaded eagerly
//! "anthropic:claude-haiku-4-5" = 80
//! "anthropic:claude-opus-4-7"  = 60
//! ```
//!
//! ## Compatibility
//!
//! `RoutedRuntime` is itself an `AgentRuntime` so it can be passed wherever
//! the existing modules expect `&dyn AgentRuntime`. New modules call
//! `query_for_role(role, req)` to opt into routing; legacy modules keep
//! using `query_blocking` and the route is bypassed (their explicit model
//! string wins).

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::config::ConfigPaths;
use crate::findings::TriageOutcome;
use crate::options::{OptionScope, OptionTarget, ToolOptionStore};
use crate::runtime::{
    AgentLoopStep, AgentQueryRequest, AgentQueryResponse, AgentRuntime, AgentToolLoopRequest,
    LoopHistoryEntry, TriageRequest,
};

/// Logical role assigned to an agent call. Each role maps to one
/// [`ModelRoute`] in `models.toml`.
///
/// Adding a new role requires:
///   1. Add the variant here.
///   2. Add a `[roles.<snake_case>]` example in the docs above.
///   3. Update [`AgentRole::as_key`] / [`AgentRole::from_key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AgentRole {
    /// Single-pass triage on a finding (existing default path).
    Triage,
    /// Cheap classifier gate before deep-audit (Phase 6).
    ClassifierGate,
    /// Tool-augmented deep auditor (Phase 5).
    DeepAuditor,
    /// Whole-codebase chunked LLM pass (Phase 7).
    FullModeMulti,
    /// Existing systems-hunt module.
    SystemsHunt,
    /// Existing carlini-threat-hunt module.
    Carlini,
    /// Existing variant-ndiff module.
    VariantNdiff,
    /// threat-model build / random.
    ThreatModel,
    /// x-ray architecture-doc module.
    XRay,
    /// patch-finding module.
    Patch,
}

impl AgentRole {
    pub fn as_key(self) -> &'static str {
        match self {
            Self::Triage => "triage",
            Self::ClassifierGate => "classifier_gate",
            Self::DeepAuditor => "deep_auditor",
            Self::FullModeMulti => "full_mode_multi",
            Self::SystemsHunt => "systems_hunt",
            Self::Carlini => "carlini",
            Self::VariantNdiff => "variant_ndiff",
            Self::ThreatModel => "threat_model",
            Self::XRay => "x_ray",
            Self::Patch => "patch",
        }
    }

    pub fn from_key(key: &str) -> Option<Self> {
        match key {
            "triage" => Some(Self::Triage),
            "classifier_gate" => Some(Self::ClassifierGate),
            "deep_auditor" => Some(Self::DeepAuditor),
            "full_mode_multi" => Some(Self::FullModeMulti),
            "systems_hunt" => Some(Self::SystemsHunt),
            "carlini" => Some(Self::Carlini),
            "variant_ndiff" => Some(Self::VariantNdiff),
            "threat_model" => Some(Self::ThreatModel),
            "x_ray" => Some(Self::XRay),
            "patch" => Some(Self::Patch),
            _ => None,
        }
    }

    /// Option-store key used to set this role's model from `setg`/`set`:
    ///   `setg MODEL_DEEP_AUDITOR anthropic:claude-opus-4-7`
    pub fn option_store_key(self) -> String {
        format!("MODEL_{}", self.as_key().to_uppercase())
    }

    /// Iterate over every role. Used to enumerate option specs and
    /// docs surfaces.
    pub const fn all() -> &'static [Self] {
        &[
            Self::Triage,
            Self::ClassifierGate,
            Self::DeepAuditor,
            Self::FullModeMulti,
            Self::SystemsHunt,
            Self::Carlini,
            Self::VariantNdiff,
            Self::ThreatModel,
            Self::XRay,
            Self::Patch,
        ]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelRoute {
    pub primary: String,
    /// Reserved for future explicit-consent fallback support.
    ///
    /// Loading rejects non-empty values today so a stale config cannot
    /// silently route a Claude task to Codex/OpenAI or vice versa.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallbacks: Vec<String>,
}

impl ModelRoute {
    pub fn new(primary: impl Into<String>) -> Self {
        Self {
            primary: primary.into(),
            fallbacks: Vec::new(),
        }
    }

    /// Return the configured primary on the first attempt only.
    ///
    /// Non-zero attempts return `None` to uphold the no-silent-model-fallback
    /// policy. Same-model transport retries live inside concrete runtime
    /// adapters and reuse the exact same model string.
    pub fn pick(&self, attempt: u32) -> Option<&str> {
        if attempt == 0 {
            return Some(self.primary.as_str());
        }
        None
    }
}

/// Loaded routing table.
#[derive(Debug, Clone, Default)]
pub struct AgentRouter {
    routes: BTreeMap<AgentRole, ModelRoute>,
    default_model: Option<String>,
    concurrency_caps: BTreeMap<String, u32>,
}

impl AgentRouter {
    /// Empty router — every role returns `None` from `pick`. The
    /// [`RoutedRuntime`] then falls back to the operator's
    /// `ctx.config.model`.
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn route(&self, role: AgentRole) -> Option<&ModelRoute> {
        self.routes.get(&role)
    }

    pub fn pick(&self, role: AgentRole, attempt: u32) -> Option<&str> {
        self.routes.get(&role).and_then(|route| route.pick(attempt))
    }

    pub fn default_model(&self) -> Option<&str> {
        self.default_model.as_deref()
    }

    pub fn concurrency_cap(&self, model: &str) -> Option<u32> {
        self.concurrency_caps.get(model).copied()
    }

    /// Load `models.toml` from the home dir and (if present) the project
    /// dir. Project entries override home entries on the same role.
    /// The path can also be overridden via `KUZUSHI_MODELS_FILE`.
    pub fn load(paths: &ConfigPaths) -> Result<Self> {
        let mut router = Self::empty();

        // 1. Home path (or env override).
        let home_path = env::var("KUZUSHI_MODELS_FILE")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| paths.home_dir.join(".kuzushi").join("models.toml"));
        if home_path.exists() {
            router.merge_file(&home_path)?;
        }

        // 2. Project-local override.
        if let Some(target) = paths.target_dir.as_ref() {
            let project_path = target.join(".kuzushi").join("models.toml");
            if project_path.exists() {
                router.merge_file(&project_path)?;
            }
        }

        Ok(router)
    }

    fn merge_file(&mut self, path: &Path) -> Result<()> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("could not read {}", path.display()))?;
        let parsed: ModelsTomlFile =
            toml::from_str(&raw).with_context(|| format!("could not parse {}", path.display()))?;

        if let Some(default) = parsed.default_model {
            self.default_model = Some(default);
        }
        for (key, route) in parsed.roles {
            let Some(role) = AgentRole::from_key(&key) else {
                anyhow::bail!(
                    "unknown agent role {key:?} in {} — known: triage, classifier_gate, \
                     deep_auditor, full_mode_multi, systems_hunt, carlini, variant_ndiff, \
                     threat_model, x_ray, patch",
                    path.display()
                );
            };
            if !route.fallbacks.is_empty() {
                anyhow::bail!(
                    "role {key:?} in {} declares model fallbacks, but Kuzushi \
                     requires explicit operator consent for model changes; keep \
                     only `primary` or run separate explicit attempts",
                    path.display()
                );
            }
            self.routes.insert(role, route);
        }
        for (model, cap) in parsed.concurrency {
            self.concurrency_caps.insert(model, cap);
        }
        Ok(())
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelsTomlFile {
    #[serde(default)]
    default_model: Option<String>,
    #[serde(default)]
    roles: BTreeMap<String, ModelRoute>,
    #[serde(default)]
    concurrency: BTreeMap<String, u32>,
}

/// Wraps an existing [`AgentRuntime`] and substitutes the model based on
/// the agent role. Implements `AgentRuntime` itself so legacy callers see
/// a transparent passthrough.
pub struct RoutedRuntime {
    inner: Arc<dyn AgentRuntime>,
    router: Arc<AgentRouter>,
    /// `ctx.config.model` — used when no route matches the role.
    operator_default: Option<String>,
    /// Snapshot of operator-settable role models from `ToolOptionStore`.
    /// Set via [`RoutedRuntime::with_option_store`] at construction; not
    /// re-read per-call so a hot route stays consistent within a scan.
    /// Operators set these from the shell:
    ///   `setg MODEL_DEEP_AUDITOR anthropic:claude-opus-4-7`
    option_overrides: BTreeMap<AgentRole, String>,
}

impl RoutedRuntime {
    pub fn new(
        inner: Arc<dyn AgentRuntime>,
        router: Arc<AgentRouter>,
        operator_default: Option<String>,
    ) -> Self {
        Self {
            inner,
            router,
            operator_default,
            option_overrides: BTreeMap::new(),
        }
    }

    /// Snapshot per-role model overrides from `ToolOptionStore`. Operators
    /// set these via `setg MODEL_<ROLE>` from the shell; values at the
    /// `(Global, All)` binding apply across every module.
    pub fn with_option_store(mut self, store: &ToolOptionStore) -> Self {
        if let Some(values) = store.values_for(OptionScope::Global, &OptionTarget::All) {
            for role in AgentRole::all() {
                if let Some(value) = values.get(&role.option_store_key()) {
                    if let Some(s) = value.as_str() {
                        let trimmed = s.trim();
                        if !trimmed.is_empty() {
                            self.option_overrides.insert(*role, trimmed.to_string());
                        }
                    }
                }
            }
        }
        self
    }

    pub fn router(&self) -> &AgentRouter {
        &self.router
    }

    /// Resolve the model for a role.
    ///
    /// Precedence (highest first):
    ///   1. `req.model` if non-empty *and* not equal to the operator default
    ///      (caller already chose a specific model — respect it).
    ///   2. `ToolOptionStore` `MODEL_<ROLE>` at `(Global, All)`.
    ///   3. Role map at `attempt`.
    ///   4. Operator default (`ctx.config.model`).
    ///   5. Router's `default_model`.
    pub fn resolve_model(
        &self,
        role: AgentRole,
        attempt: u32,
        explicit: Option<&str>,
    ) -> Option<String> {
        // 1. Explicit override wins, but ignore the operator default — that's a
        //    boilerplate fill from the caller, not a deliberate choice.
        if let Some(explicit) = explicit {
            let trimmed = explicit.trim();
            if !trimmed.is_empty()
                && Some(trimmed) != self.operator_default.as_deref().map(str::trim)
            {
                return Some(trimmed.to_string());
            }
        }
        // 2. Operator-set option override.
        if attempt == 0 {
            if let Some(override_) = self.option_overrides.get(&role) {
                return Some(override_.clone());
            }
        }
        // 3. Role map.
        if let Some(picked) = self.router.pick(role, attempt) {
            return Some(picked.to_string());
        }
        // 4. Operator default.
        if let Some(default) = &self.operator_default {
            let trimmed = default.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
        // 5. Router-wide default from models.toml.
        self.router.default_model().map(str::to_string)
    }

    /// Single-attempt query routed by role. The router never changes models
    /// after a failure; callers that want another model must issue an explicit
    /// request with that model.
    pub fn query_for_role(
        &self,
        role: AgentRole,
        mut request: AgentQueryRequest,
    ) -> Result<AgentQueryResponse> {
        let model = self
            .resolve_model(role, 0, Some(&request.model))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no model configured for role {:?}: set models.toml [roles.{}] \
                     or pass an explicit ctx.config.model",
                    role,
                    role.as_key()
                )
            })?;
        request.model = model;
        self.inner.query_blocking(request)
    }

    /// Triage routed by role.
    pub fn triage_for_role(
        &self,
        role: AgentRole,
        mut request: TriageRequest,
    ) -> Result<TriageOutcome> {
        let model = self
            .resolve_model(role, 0, Some(&request.model))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no model configured for role {:?}: set models.toml [roles.{}] \
                     or pass an explicit ctx.config.model",
                    role,
                    role.as_key()
                )
            })?;
        request.model = model;
        self.inner.triage_finding_blocking(request)
    }
}

#[async_trait]
impl AgentRuntime for RoutedRuntime {
    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        self.inner.query_blocking(request)
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
        self.inner.triage_finding_blocking(request)
    }

    fn supports_tools(&self) -> bool {
        self.inner.supports_tools()
    }

    fn next_step_blocking(
        &self,
        request: &AgentToolLoopRequest,
        history: &[LoopHistoryEntry],
    ) -> Result<AgentLoopStep> {
        self.inner.next_step_blocking(request, history)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Finding, Severity};
    use std::path::PathBuf;
    use std::sync::Mutex;

    /// In-memory recorder runtime: captures the last request's model so we
    /// can assert what the router substituted.
    struct RecorderRuntime {
        last_query_model: Mutex<Option<String>>,
        last_triage_model: Mutex<Option<String>>,
    }

    impl RecorderRuntime {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                last_query_model: Mutex::new(None),
                last_triage_model: Mutex::new(None),
            })
        }
    }

    #[async_trait]
    impl AgentRuntime for RecorderRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            *self.last_query_model.lock().unwrap() = Some(request.model.clone());
            Ok(AgentQueryResponse {
                text: "ok".to_string(),
                structured: None,
            })
        }

        fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
            *self.last_triage_model.lock().unwrap() = Some(request.model.clone());
            Ok(TriageOutcome {
                verdict: crate::findings::TriageVerdict::NeedsReview,
                confidence: 0.0,
                rationale: "test".to_string(),
            })
        }
    }

    fn synthetic_finding() -> Finding {
        Finding::new_tool(
            "test",
            "rule",
            "src/foo.rs",
            10,
            Some(10),
            Severity::High,
            "msg",
        )
    }

    fn write_models_toml(home: &Path, body: &str) -> PathBuf {
        let dir = home.join(".kuzushi");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("models.toml");
        fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn empty_router_returns_none_for_all_roles() {
        let r = AgentRouter::empty();
        for role in [
            AgentRole::Triage,
            AgentRole::DeepAuditor,
            AgentRole::FullModeMulti,
        ] {
            assert!(
                r.pick(role, 0).is_none(),
                "role {role:?} unexpectedly mapped"
            );
        }
        assert!(r.default_model().is_none());
    }

    #[test]
    fn loads_routes_from_home_models_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        write_models_toml(
            &home,
            r#"
default_model = "anthropic:claude-sonnet-4-6"

[roles.classifier_gate]
primary = "anthropic:claude-haiku-4-5"

[roles.deep_auditor]
primary = "anthropic:claude-opus-4-7"

[concurrency]
"anthropic:claude-haiku-4-5" = 80
"anthropic:claude-opus-4-7"  = 60
"#,
        );
        let r = AgentRouter::load(&ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap();

        assert_eq!(r.default_model(), Some("anthropic:claude-sonnet-4-6"));
        assert_eq!(
            r.pick(AgentRole::ClassifierGate, 0),
            Some("anthropic:claude-haiku-4-5")
        );
        assert_eq!(r.pick(AgentRole::ClassifierGate, 1), None);

        assert_eq!(
            r.pick(AgentRole::DeepAuditor, 0),
            Some("anthropic:claude-opus-4-7")
        );
        assert_eq!(r.pick(AgentRole::DeepAuditor, 1), None);

        assert_eq!(r.concurrency_cap("anthropic:claude-haiku-4-5"), Some(80));
        assert_eq!(r.concurrency_cap("anthropic:claude-opus-4-7"), Some(60));
    }

    #[test]
    fn project_local_overrides_home() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let target = tmp.path().join("project");
        write_models_toml(
            &home,
            r#"
[roles.deep_auditor]
primary = "home-model"
"#,
        );
        write_models_toml(
            &target,
            r#"
[roles.deep_auditor]
primary = "project-model"
"#,
        );
        let r = AgentRouter::load(&ConfigPaths {
            home_dir: home,
            target_dir: Some(target),
        })
        .unwrap();
        assert_eq!(r.pick(AgentRole::DeepAuditor, 0), Some("project-model"));
    }

    #[test]
    fn rejects_unknown_role_key() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        write_models_toml(
            &home,
            r#"
[roles.fictional_role]
primary = "x"
"#,
        );
        let err = AgentRouter::load(&ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("fictional_role"), "{}", err);
    }

    #[test]
    fn rejects_model_fallbacks_without_explicit_consent() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        write_models_toml(
            &home,
            r#"
[roles.deep_auditor]
primary = "anthropic:claude-opus-4-7"
fallbacks = ["openai:o3"]
"#,
        );
        let err = AgentRouter::load(&ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("model fallbacks"), "{err}");
    }

    #[test]
    fn routed_runtime_substitutes_model_for_role() {
        let inner = RecorderRuntime::new();
        let mut router = AgentRouter::empty();
        router.routes.insert(
            AgentRole::DeepAuditor,
            ModelRoute::new("anthropic:claude-opus-4-7"),
        );
        let routed = RoutedRuntime::new(
            inner.clone(),
            Arc::new(router),
            Some("anthropic:claude-sonnet-4-6".to_string()),
        );

        // The caller sends ctx.config.model (the operator default). The
        // router must replace it with the role-specific model.
        let response = routed
            .query_for_role(
                AgentRole::DeepAuditor,
                AgentQueryRequest::new(
                    "anthropic:claude-sonnet-4-6",
                    PathBuf::from("/tmp"),
                    "sys",
                    "user",
                ),
            )
            .unwrap();
        assert_eq!(response.text, "ok");
        assert_eq!(
            inner.last_query_model.lock().unwrap().as_deref(),
            Some("anthropic:claude-opus-4-7"),
            "router should have substituted the role-specific model"
        );
    }

    #[test]
    fn explicit_non_default_model_wins_over_role_map() {
        let inner = RecorderRuntime::new();
        let mut router = AgentRouter::empty();
        router
            .routes
            .insert(AgentRole::DeepAuditor, ModelRoute::new("role-model"));
        let routed = RoutedRuntime::new(
            inner.clone(),
            Arc::new(router),
            Some("operator-default".to_string()),
        );

        // Caller passed an explicit per-task model that's NOT the operator default.
        // That should win over the role map.
        routed
            .query_for_role(
                AgentRole::DeepAuditor,
                AgentQueryRequest::new("per-task-override", PathBuf::from("/tmp"), "sys", "user"),
            )
            .unwrap();
        assert_eq!(
            inner.last_query_model.lock().unwrap().as_deref(),
            Some("per-task-override")
        );
    }

    #[test]
    fn errors_when_no_model_resolvable() {
        let inner = RecorderRuntime::new();
        let routed = RoutedRuntime::new(
            inner.clone(),
            Arc::new(AgentRouter::empty()),
            None, // no operator default
        );

        let err = routed
            .query_for_role(
                AgentRole::DeepAuditor,
                AgentQueryRequest::new("", PathBuf::from("/tmp"), "sys", "user"),
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("no model configured"), "{err}");
        assert!(err.contains("deep_auditor"), "{err}");
    }

    #[test]
    fn legacy_query_blocking_passes_through_unchanged() {
        let inner = RecorderRuntime::new();
        let routed = RoutedRuntime::new(
            inner.clone(),
            Arc::new(AgentRouter::empty()),
            Some("operator-default".to_string()),
        );
        // No role — calls the AgentRuntime trait method directly.
        routed
            .query_blocking(AgentQueryRequest::new(
                "explicit-legacy",
                PathBuf::from("/tmp"),
                "sys",
                "user",
            ))
            .unwrap();
        assert_eq!(
            inner.last_query_model.lock().unwrap().as_deref(),
            Some("explicit-legacy"),
            "legacy path must not rewrite the model"
        );
    }

    #[test]
    fn option_store_override_takes_precedence_over_role_map() {
        let inner = RecorderRuntime::new();
        let mut router = AgentRouter::empty();
        router
            .routes
            .insert(AgentRole::DeepAuditor, ModelRoute::new("toml-model"));

        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Global,
            OptionTarget::All,
            "MODEL_DEEP_AUDITOR",
            serde_json::Value::String("setg-model".to_string()),
        );

        let routed = RoutedRuntime::new(
            inner.clone(),
            Arc::new(router),
            Some("operator-default".to_string()),
        )
        .with_option_store(&store);

        routed
            .query_for_role(
                AgentRole::DeepAuditor,
                AgentQueryRequest::new("operator-default", PathBuf::from("/tmp"), "sys", "user"),
            )
            .unwrap();
        assert_eq!(
            inner.last_query_model.lock().unwrap().as_deref(),
            Some("setg-model"),
            "operator-set MODEL_DEEP_AUDITOR must beat models.toml"
        );
    }

    #[test]
    fn option_store_keys_are_uppercased_role_keys() {
        assert_eq!(
            AgentRole::DeepAuditor.option_store_key(),
            "MODEL_DEEP_AUDITOR"
        );
        assert_eq!(
            AgentRole::ClassifierGate.option_store_key(),
            "MODEL_CLASSIFIER_GATE"
        );
        assert_eq!(AgentRole::Triage.option_store_key(), "MODEL_TRIAGE");
    }

    #[test]
    fn triage_routing_works_too() {
        let inner = RecorderRuntime::new();
        let mut router = AgentRouter::empty();
        router
            .routes
            .insert(AgentRole::Triage, ModelRoute::new("triage-model"));
        let routed = RoutedRuntime::new(
            inner.clone(),
            Arc::new(router),
            Some("operator-default".to_string()),
        );
        routed
            .triage_for_role(
                AgentRole::Triage,
                TriageRequest {
                    model: "operator-default".to_string(),
                    cwd: PathBuf::from("/tmp"),
                    finding: synthetic_finding(),
                    prompt_template: None,
                },
            )
            .unwrap();
        assert_eq!(
            inner.last_triage_model.lock().unwrap().as_deref(),
            Some("triage-model")
        );
    }
}

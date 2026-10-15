use super::*;

#[macro_use]
mod initial_state;

pub(crate) const UI_AUTO_OPEN_ACTIVITY_OPTION: &str = "ui.auto_open_activity";
pub(crate) const UI_AUTO_OPEN_VIZ_OPTION: &str = "ui.auto_open_viz";
pub(crate) const UI_AUTONOMY_OPTION: &str = "ui.autonomy";
pub(crate) const UI_RAIL_OPTION: &str = "ui.rail";
pub(crate) const UI_NOTIFY_OPTION: &str = "ui.notify";

/// Operator preference for the Activity view's auto-open behaviour at
/// scan/tool start. Default ON. `setg ui.auto_open_activity false` wins over
/// the compatibility env var `KUZUSHI_AUTO_OPEN_ACTIVITY=false`.
fn read_auto_open_activity_pref(option_store: &ToolOptionStore) -> bool {
    read_bool_pref(
        option_store,
        UI_AUTO_OPEN_ACTIVITY_OPTION,
        "KUZUSHI_AUTO_OPEN_ACTIVITY",
    )
}

/// Operator preference for auto-opening the relevant security-viz page when
/// its artifact is generated. Default ON. `setg ui.auto_open_viz false` wins
/// over the compatibility env var `KUZUSHI_AUTO_OPEN_VIZ=false`.
fn read_auto_open_viz_pref(option_store: &ToolOptionStore) -> bool {
    read_bool_pref(
        option_store,
        UI_AUTO_OPEN_VIZ_OPTION,
        "KUZUSHI_AUTO_OPEN_VIZ",
    )
}

pub(crate) fn refresh_ui_prefs_from_store(app: &mut ShellApp) {
    let auto_open_activity = read_auto_open_activity_pref(app.option_store());
    let auto_open_viz = read_auto_open_viz_pref(app.option_store());
    // Default ON; no env compat — rail and notify are options-first from birth.
    let rail_enabled = stored_bool_pref(app.option_store(), UI_RAIL_OPTION).unwrap_or(true);
    let notify_enabled = stored_bool_pref(app.option_store(), UI_NOTIFY_OPTION).unwrap_or(true);
    app.ui_mut().set_auto_open_activity(auto_open_activity);
    app.ui_mut().set_auto_open_viz(auto_open_viz);
    app.ui_mut().set_rail_enabled(rail_enabled);
    app.ui_mut().set_notify_enabled(notify_enabled);
    if let Some(posture) = stored_autonomy_pref(app.option_store()) {
        app.set_autonomy(posture);
    }
}

fn stored_autonomy_pref(option_store: &ToolOptionStore) -> Option<kuzushi_core::AutonomyPosture> {
    option_store
        .effective_stored_values("kuzushi:ui")
        .get(UI_AUTONOMY_OPTION)
        .and_then(serde_json::Value::as_str)
        .and_then(kuzushi_core::AutonomyPosture::parse)
}

fn read_bool_pref(option_store: &ToolOptionStore, option_name: &str, env_key: &str) -> bool {
    stored_bool_pref(option_store, option_name).unwrap_or_else(|| read_bool_env(env_key))
}

fn stored_bool_pref(option_store: &ToolOptionStore, option_name: &str) -> Option<bool> {
    option_store
        .effective_stored_values("kuzushi:ui")
        .get(option_name)
        .and_then(json_bool)
}

pub(crate) fn json_bool(value: &serde_json::Value) -> Option<bool> {
    match value {
        serde_json::Value::Bool(value) => Some(*value),
        serde_json::Value::String(value) => parse_bool_pref(value),
        _ => None,
    }
}

pub(crate) fn parse_bool_pref(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

pub(crate) fn active_model_override_from_input(
    input: &serde_json::Value,
    config: &V2Config,
) -> Option<String> {
    let model = input.get("model")?.as_str()?.trim();
    if model.is_empty() || Some(model) == config.model.as_deref() {
        return None;
    }
    Some(model.to_string())
}

/// A default-true boolean env knob (`0|false|no|off` → false; unset → true).
fn read_bool_env(key: &str) -> bool {
    match std::env::var(key) {
        Ok(value) => !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        ),
        Err(_) => true,
    }
}

fn context_snapshot_target_path(target: Option<&WorkspaceTarget>) -> Option<PathBuf> {
    target.map(|target| kuzushi_core::context_snapshot_path(target.root()))
}

impl ShellApp {
    pub fn new(config: V2Config, target: Option<&WorkspaceTarget>) -> Self {
        Self::with_registry(config, target, ModuleRegistry::with_v2_builtins())
    }

    pub fn with_registry(
        config: V2Config,
        target: Option<&WorkspaceTarget>,
        registry: ModuleRegistry,
    ) -> Self {
        Self::with_registry_and_transcript(config, target, registry, None)
    }

    pub(crate) fn with_registry_and_transcript(
        config: V2Config,
        target: Option<&WorkspaceTarget>,
        registry: ModuleRegistry,
        transcript: Option<kuzushi_core::session_transcript::SessionRecorder>,
    ) -> Self {
        let (option_store, option_store_error) = persistent_option_store(target);
        let session_budget_usd = config.operator.session_budget_usd;
        let trusted_workflow_auto_accept = config.operator.trusted_workflow_auto_accept;
        let mut app = shell_app_initial_state!(
            config,
            target,
            option_store,
            registry,
            session_budget_usd,
            trusted_workflow_auto_accept
        );
        if let Some(transcript) = transcript {
            app.attach_session_transcript(transcript);
        }
        Self::hydrate_initial_workspace(&mut app, target);
        app.start_answer_recovery();
        app.announce_startup(option_store_error, target.is_some());
        app
    }

    fn hydrate_initial_workspace(app: &mut Self, target: Option<&WorkspaceTarget>) {
        refresh_ui_prefs_from_store(app);
        app.refresh_phase_attempt_projection();
        if let Some(target) = target {
            app.start_active_target_facts(target.root().to_path_buf());
            if let Err(error) = app.refresh_context_view() {
                app.log(
                    "context",
                    format!("could not hydrate the initial context snapshot: {error}"),
                );
            }
        }
        // Git metadata hydrates via the background view-hydration baseline;
        // a synchronous prewarm here blocks first paint for seconds on
        // monorepo-scale targets (`git status` alone).
        app.hydrate_persisted_scene_snapshots(target.map(|target| target.root()));
        app.refresh_program_scope();
    }

    /// Post-construction setup: session model/thinking-level, the startup
    /// banner logs, persisted history load, and the first-run onboarding phase.
    fn announce_startup(&mut self, option_store_error: Option<String>, has_target: bool) {
        self.apply_configured_model_reasoning();
        self.log("system", "kuzushi shell");
        self.log("startup", self.startup_summary_line());
        if let Some(error) = option_store_error {
            self.log("options", error);
        }
        // The first-finding hint is rendered in the catalog body via
        // `next_action_line` + `first_finding_hint`; keeping a duplicate
        // copy in the transcript wasted one of only two visible log rows.
        self.log(
            "help",
            "type `next` to continue the guided workflow · `help` for commands · `?<text>` to ask the agent",
        );
        if has_target {
            self.refresh_findings(false);
        }
        self.load_persisted_history();
        self.apply_initial_onboarding_phase();
    }

    fn apply_configured_model_reasoning(&mut self) {
        if let Some(level) = self.config().runtime.thinking_level.clone() {
            self.set_session_thinking_level(Some(level));
            return;
        }
        let choice = self
            .config()
            .model
            .as_deref()
            .and_then(model_choice_index_by_id)
            .and_then(|index| model_choices().get(index));
        if let Some(choice) = choice {
            self.set_session_thinking_level(Some(choice.thinking_level.to_string()));
        }
    }
}

#[cfg(test)]
mod initial_context_tests {
    use super::*;

    #[test]
    fn explicit_configured_reasoning_wins_over_catalog_suggestions() {
        for level in ["low", "medium", "high"] {
            let mut config = V2Config::default();
            config.model = Some("openai-codex:gpt-5.5".into());
            config.runtime.thinking_level = Some(level.into());
            let mut app = ShellApp::new(config, None);
            assert_eq!(app.session_thinking_level(), Some(level));
            let root = tempfile::tempdir().unwrap();
            std::fs::write(
                root.path().join("main.rs"),
                "// Inert owned source. Never executed.\n",
            )
            .unwrap();
            app.set_target(Some(root.path().to_owned()));
            app.plan_workflow_proposal("Inspect owned context", None)
                .unwrap();
            assert_eq!(
                app.context_generation().unwrap().context_input["thinkingLevel"],
                level
            );
            assert!(!app.has_running_work());
        }
    }

    #[test]
    fn model_catalog_suggestions_do_not_change_configured_reasoning_at_startup() {
        for (model, expected_effort) in [
            ("openai-codex:gpt-5.4", Some("xhigh")),
            ("openai:operator-custom-model", None),
        ] {
            let mut config = V2Config::default();
            config.model = Some(model.into());
            let app = ShellApp::new(config, None);
            assert_eq!(app.config().model.as_deref(), Some(model));
            assert_eq!(app.session_thinking_level(), expected_effort);
        }
    }

    #[test]
    fn shell_startup_projects_an_existing_context_snapshot() {
        let target = tempfile::tempdir().unwrap();
        let snapshot_path = kuzushi_core::context_snapshot_path(target.path());
        std::fs::create_dir_all(snapshot_path.parent().unwrap()).unwrap();
        std::fs::write(
            snapshot_path,
            serde_json::json!({
                "target": target.path(),
                "filesIndexed": 42,
                "repoContext": { "languages": ["Rust"], "frameworks": [] }
            })
            .to_string(),
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();

        let app = ShellApp::new(V2Config::default(), Some(&workspace));

        assert!(app.domain().context_view().exists);
        assert_eq!(app.domain().context_view().files_indexed, Some(42));
    }
}

pub(crate) fn persistent_option_store(
    target: Option<&WorkspaceTarget>,
) -> (ToolOptionStore, Option<String>) {
    let paths = match kuzushi_core::ConfigPaths::from_target(target.map(WorkspaceTarget::root)) {
        Ok(paths) => paths,
        Err(error) => return (ToolOptionStore::new(), Some(error.to_string())),
    };
    match ToolOptionStore::load_persistent(
        &operator_options_path(&paths),
        paths.project_options_path().as_deref(),
    ) {
        Ok(store) => (store, None),
        Err(error) => (ToolOptionStore::new(), Some(error.to_string())),
    }
}

#[cfg(not(test))]
fn operator_options_path(paths: &kuzushi_core::ConfigPaths) -> std::path::PathBuf {
    paths.global_options_path()
}

#[cfg(test)]
fn operator_options_path(paths: &kuzushi_core::ConfigPaths) -> std::path::PathBuf {
    paths
        .target_dir
        .clone()
        .unwrap_or_else(std::env::temp_dir)
        .join(".kuzushi-test-operator-options-absent.json")
}

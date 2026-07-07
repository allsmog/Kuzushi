use super::*;

#[macro_use]
mod initial_state;

pub(crate) const UI_AUTO_OPEN_ACTIVITY_OPTION: &str = "ui.auto_open_activity";
pub(crate) const UI_AUTO_OPEN_VIZ_OPTION: &str = "ui.auto_open_viz";
pub(crate) const UI_WORKBENCH_DEPTH_STACK_OPTION: &str = "ui.workbench_depth_stack";

/// Opt-in depth-stack Workbench review surface. Default OFF — the four-pane
/// ring stays the default. `setg ui.workbench_depth_stack true` enables it.
fn read_workbench_depth_stack_pref(option_store: &ToolOptionStore) -> bool {
    stored_bool_pref(option_store, UI_WORKBENCH_DEPTH_STACK_OPTION).unwrap_or(false)
}

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

pub(crate) fn refresh_auto_open_prefs_from_store(app: &mut ShellApp) {
    let auto_open_activity = read_auto_open_activity_pref(app.option_store());
    let auto_open_viz = read_auto_open_viz_pref(app.option_store());
    let depth_stack = read_workbench_depth_stack_pref(app.option_store());
    app.ui_mut().set_auto_open_activity(auto_open_activity);
    app.ui_mut().set_auto_open_viz(auto_open_viz);
    app.router.workbench_mut().set_depth_stack(depth_stack);
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
        mut config: V2Config,
        target: Option<&WorkspaceTarget>,
        registry: ModuleRegistry,
    ) -> Self {
        let ready_default = target
            .is_some()
            .then(|| ready_default_model_choice_index(config.model.as_deref()))
            .flatten();
        if let Some(choice) = ready_default.and_then(|index| model_choices().get(index)) {
            config.model = Some(choice.id.to_string());
        }
        let selected_model_index = preferred_model_choice_index(&config);
        let (option_store, option_store_error) = persistent_option_store(target);
        let session_budget_usd = config.operator.session_budget_usd;
        let trusted_workflow_auto_accept = config.operator.trusted_workflow_auto_accept;
        let mut app = shell_app_initial_state!(
            config,
            target,
            option_store,
            registry,
            selected_model_index,
            session_budget_usd,
            trusted_workflow_auto_accept
        );
        refresh_auto_open_prefs_from_store(&mut app);
        app.hydrate_persisted_scene_snapshots(target.map(|target| target.root()));
        app.refresh_program_scope();
        app.announce_startup(
            selected_model_index,
            ready_default,
            option_store_error,
            target.is_some(),
        );
        app
    }

    /// Post-construction setup: session model/thinking-level, the startup
    /// banner logs, persisted history load, and the first-run onboarding phase.
    fn announce_startup(
        &mut self,
        selected_model_index: usize,
        ready_default: Option<usize>,
        option_store_error: Option<String>,
        has_target: bool,
    ) {
        self.apply_session_model(selected_model_index, ready_default);
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
        // Align the autonomy dial to where the engagement actually is, never
        // above the project cap. Must run after findings load so the derived
        // journey phase reflects workspace reality.
        self.initialize_default_autonomy();
    }

    fn apply_session_model(&mut self, selected_model_index: usize, ready_default: Option<usize>) {
        if let Some(choice) = model_choices().get(selected_model_index) {
            self.set_session_thinking_level(Some(choice.thinking_level.to_string()));
        }
        if let Some(choice) = ready_default.and_then(|index| model_choices().get(index)) {
            self.log(
                "model",
                format!(
                    "{} / {} ready; using as session default",
                    model_choice_display_selector(choice),
                    choice.thinking_level
                ),
            );
        }
    }
}

fn persistent_option_store(target: Option<&WorkspaceTarget>) -> (ToolOptionStore, Option<String>) {
    let paths = match kuzushi_core::ConfigPaths::from_target(target.map(WorkspaceTarget::root)) {
        Ok(paths) => paths,
        Err(error) => return (ToolOptionStore::new(), Some(error.to_string())),
    };
    match ToolOptionStore::load_persistent(
        &paths.global_options_path(),
        paths.project_options_path().as_deref(),
    ) {
        Ok(store) => (store, None),
        Err(error) => (ToolOptionStore::new(), Some(error.to_string())),
    }
}

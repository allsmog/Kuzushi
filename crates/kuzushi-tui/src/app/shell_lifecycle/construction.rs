use super::*;

pub(crate) const UI_AUTO_OPEN_ACTIVITY_OPTION: &str = "ui.auto_open_activity";
pub(crate) const UI_AUTO_OPEN_VIZ_OPTION: &str = "ui.auto_open_viz";

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
    app.auto_open_activity = read_auto_open_activity_pref(&app.option_store);
    app.auto_open_viz = read_auto_open_viz_pref(&app.option_store);
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

macro_rules! shell_app_initial_state {
    ($config:expr, $target:expr, $option_store:expr, $registry:expr, $selected_model_index:expr, $session_budget_usd:expr, $trusted_workflow_auto_accept:expr) => {{
        Self {
            input: String::new(),
            cursor: 0,
            history_index: None,
            history_draft: String::new(),
            last_cleared_input: None,
            completion_cycle: None,
            log: Vec::new(),
            target: ($target).map(|target| target.root().to_path_buf()),
            active_scope: None,
            task_durations: crate::app::TaskDurationStore::load(
                ($target).map(|target| target.root()),
            ),
            focused_module: None,
            shell_view: ShellView::Catalog,
            prev_shell_view: None,
            nav_history: Vec::new(),
            catalog_expanded: false,
            catalog_cursor: 0,
            recommend_cursor: 0,
            pending_patch: None,
            confirm_allowlist: std::collections::BTreeSet::new(),
            confirm_denylist: std::collections::BTreeSet::new(),
            config: $config,
            registry: $registry,
            option_store: $option_store.clone(),
            command_history: Vec::new(),
            history_search: None,
            session_cost_usd: 0.0,
            last_tool_cost_usd: None,
            selected_model_index: $selected_model_index,
            context_view: default_context_snapshot_view(
                ($target).map(|target| kuzushi_core::context_snapshot_path(target.root())),
            ),
            workspace_view: default_workspace_view($target),
            kb_view: KnowledgeBaseView {
                module_id: "context".to_string(),
                store_path: None,
                attachments: Vec::new(),
                artifacts: Vec::new(),
            },
            pwn_view: PwnView::default(),
            auth_login: None,
            agent_chat: None,
            session_thinking_level: None,
            findings: Vec::new(),
            selected_finding: None,
            workbench_focus: crate::app::WorkbenchPane::Findings,
            workbench_page: None,
            workbench_center_mode: crate::app::WorkbenchCenterMode::default(),
            workbench_scroll: crate::app::WorkbenchPaneScroll::default(),
            workbench_cache: std::cell::RefCell::new(WorkbenchCache::default()),
            scan: None,
            should_quit: false,
            ctrl_c_armed_at: None,
            session_budget_usd: $session_budget_usd,
            advisory: AdvisoryState::default(),
            live_activity: None,
            trusted_workflow_auto_accept: $trusted_workflow_auto_accept,
            pending_chain: None,
            pending_prereq_prompt: None,
            pending_plan: None,
            plan_cursor: 0,
            plan_skipped: BTreeSet::new(),
            palette_query: String::new(),
            palette_cursor: 0,
            model_picker_cursor: 0,
            auth_picker_cursor: 0,
            auth_key_draft: String::new(),
            target_picker_cursor: 0,
            target_candidates: Vec::new(),
            file_picker_files: Vec::new(),
            file_picker_query: String::new(),
            file_picker_cursor: 0,
            file_picker_truncated: false,
            file_picker_return_view: None,
            planning_cursor: 0,
            planning_selected: BTreeSet::new(),
            planning_tasks: Vec::new(),
            planning_run_queue: std::collections::VecDeque::new(),
            planning_running_tool: None,
            workflow_phase: None,
            target_kind: None,
            planning_rebuild: BTreeSet::new(),
            picker_focus: crate::app::PickerFocus::List,
            planning_option_cursor: 0,
            planning_option_overrides: std::collections::BTreeMap::new(),
            planning_option_edit: None,
            planning_option_error: None,
            planning_failed: Vec::new(),
            planning_skipped_phases: BTreeSet::new(),
            planning_adjustments: std::collections::BTreeMap::new(),
            model_recommended_tasks: None,
            tune_cursor: 0,
            prompts_cursor: 0,
            actor_detail_filter: ActorDetailFilter::All,
            planner_running: false,
            plan_abort_requested: false,
            pending_threat_patch: None,
            threat_worker_running: false,
            threat_abort_requested: false,
            chains: Vec::new(),
            story_return_view: None,
            findings_cursor: 0,
            help_scroll: 0,
            help_filter: None,
            tools_scroll: 0,
            tools_filter: None,
            modules_scroll: 0,
            history_scroll: 0,
            kb_scroll: 0,
            logs_scroll: 0,
            program_scope: None,
            last_char_at: None,
            scroll_offset: 0,
            spinner_phase: 0,
            last_spinner_advance: None,
            force_full_redraw: false,
            recon_snapshot: None,
            carlini_snapshot: None,
            agentic_sast_snapshot: None,
            scan_progress: None,
            scan_rx: None,
            scan_cancel: None,
            tool_rx: None,
            tool_running: None,
            tool_cancel: None,
            ambient_tool: None,
            tool_run_id: None,
            active_model_override: None,
            tool_abort_requested: false,
            agent_rx: None,
            agent_cancel: None,
            plan_rx: None,
            plan_cancel: None,
            threat_rx: None,
            threat_cancel: None,
            trace_rx: None,
            activity: None,
            auto_open_activity: read_auto_open_activity_pref(&$option_store),
            scene_page: crate::scene3d::VizPage::default(),
            scene_spin: 0.6,
            scene_pitch: 0.45,
            scene_paused: false,
            last_scene_advance: None,
            auto_open_viz: read_auto_open_viz_pref(&$option_store),
            exploit_chains: Vec::new(),
            taint_flow: None,
        }
    }};
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
    }

    fn apply_session_model(&mut self, selected_model_index: usize, ready_default: Option<usize>) {
        if let Some(choice) = model_choices().get(selected_model_index) {
            self.session_thinking_level = Some(choice.thinking_level.to_string());
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

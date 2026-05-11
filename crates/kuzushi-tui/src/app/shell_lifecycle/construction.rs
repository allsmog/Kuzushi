use super::*;

impl ShellApp {
    pub fn new(config: V2Config, target: Option<&WorkspaceTarget>) -> Self {
        let selected_model_index = preferred_model_choice_index(&config);
        let (option_store, option_store_error) = persistent_option_store(target);
        let session_budget_usd = config.operator.session_budget_usd;
        let trusted_workflow_auto_accept = config.operator.trusted_workflow_auto_accept;
        let mut app = Self {
            input: String::new(),
            cursor: 0,
            history_index: None,
            history_draft: String::new(),
            last_cleared_input: None,
            completion_cycle: None,
            log: Vec::new(),
            target: target.map(|target| target.root().to_path_buf()),
            focused_module: None,
            shell_view: ShellView::Catalog,
            prev_shell_view: None,
            catalog_expanded: false,
            catalog_cursor: 0,
            pending_patch: None,
            confirm_allowlist: std::collections::BTreeSet::new(),
            confirm_denylist: std::collections::BTreeSet::new(),
            config,
            registry: ModuleRegistry::with_v2_builtins(),
            option_store,
            command_history: Vec::new(),
            session_cost_usd: 0.0,
            last_tool_cost_usd: None,
            selected_model_index,
            context_view: default_context_snapshot_view(
                target.map(|target| target.root().join(".kuzushi/context-snapshot.json")),
            ),
            workspace_view: default_workspace_view(target),
            kb_view: KnowledgeBaseView {
                module_id: "context".to_string(),
                store_path: None,
                attachments: Vec::new(),
                artifacts: Vec::new(),
            },
            agent_chat: None,
            session_thinking_level: None,
            findings: Vec::new(),
            selected_finding: None,
            scan: None,
            should_quit: false,
            ctrl_c_armed_at: None,
            session_budget_usd,
            advisory: AdvisoryState::default(),
            live_activity: None,
            trusted_workflow_auto_accept,
            pending_chain: None,
            pending_prereq_prompt: None,
            pending_plan: None,
            plan_cursor: 0,
            plan_skipped: BTreeSet::new(),
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
            tools_scroll: 0,
            modules_scroll: 0,
            history_scroll: 0,
            kb_scroll: 0,
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
            tool_run_id: None,
            tool_abort_requested: false,
            agent_rx: None,
            plan_rx: None,
            threat_rx: None,
        };
        app.log("system", "kuzushi shell");
        app.log("startup", app.startup_summary_line());
        if let Some(error) = option_store_error {
            app.log("options", error);
        }
        // The first-finding hint is rendered in the catalog body via
        // `next_action_line` + `first_finding_hint`; keeping a duplicate
        // copy in the transcript wasted one of only two visible log rows.
        app.log(
            "help",
            "type help for commands · ? <text> to ask · scan to start",
        );
        if target.is_some() {
            app.refresh_findings(false);
        }
        app
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

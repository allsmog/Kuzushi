use super::prelude::*;
use super::*;

impl ShellApp {
    pub fn new(config: V2Config, target: Option<&WorkspaceTarget>) -> Self {
        let selected_model_index = preferred_model_choice_index(&config);
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
            option_store: ToolOptionStore::new(),
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
            session_budget_usd: parse_budget_env(),
            advisory: AdvisoryState::default(),
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

    pub fn log(&mut self, prefix: impl Into<String>, body: impl Into<String>) {
        self.log.push(LogLine::new(prefix, body));
        if self.log.len() > 500 {
            let overflow = self.log.len() - 500;
            self.log.drain(0..overflow);
        }
    }

    pub fn scroll_up(&mut self, amount: u16) {
        self.scroll_offset = self.scroll_offset.saturating_sub(amount);
    }

    pub fn scroll_down(&mut self, amount: u16) {
        self.scroll_offset = self.scroll_offset.saturating_add(amount);
    }

    pub fn scroll_to_top(&mut self) {
        self.scroll_offset = 0;
    }

    pub fn scroll_to_bottom(&mut self) {
        self.scroll_offset = u16::MAX;
    }

    pub(crate) fn sync_view_change(&mut self) -> bool {
        let current = Some(self.shell_view.clone());
        if self.prev_shell_view != current {
            self.scroll_offset = 0;
            self.prev_shell_view = current;
            true
        } else {
            false
        }
    }

    pub fn first_finding_scan_command(&self) -> &'static str {
        if self.target.is_some() {
            "scan"
        } else {
            "scan ."
        }
    }

    pub fn first_finding_hint(&self) -> String {
        format!(
            "First finding: run `{}`, then `findings`.",
            self.first_finding_scan_command()
        )
    }

    pub(crate) fn startup_summary_line(&self) -> String {
        let target = self
            .target
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "none".to_string());
        format!(
            "ready: {} module(s), {} tool(s), target {target}",
            self.registry.modules().count(),
            self.registry.tools().count()
        )
    }
}

use super::*;

impl ShellApp {
    pub fn handle_command(&mut self, command: ShellCommand) {
        let previous_view = self.shell_view.clone();
        for handler in COMMAND_HANDLERS {
            if handler(self, &command) {
                self.discard_stashed_input_after_view_change(&previous_view);
                return;
            }
        }
    }

    pub fn submit_line(&mut self, raw: &str) {
        let trimmed = raw.trim();
        // Empty / whitespace-only Enter is a no-op (P-NEW-3): logging an empty
        // `>` bullet just clutters the 2-row transcript with rows the operator
        // never asked for.
        if trimmed.is_empty() {
            return;
        }
        self.last_cleared_input = None;
        self.log(">", raw.to_string());
        self.remember_command(trimmed);
        if self.handle_subverb_query(trimmed) {
            return;
        }
        if self.handle_editor_local_command(trimmed) {
            return;
        }
        self.handle_command(parse_command(raw));
    }

    /// `<group-verb> ?` lists the verb's sub-verbs inline. Editor-local so it
    /// adds no `ShellCommand` route; the listing comes from the same
    /// `subverb_listing` table Tab-completion uses, so they never drift.
    fn handle_subverb_query(&mut self, trimmed: &str) -> bool {
        let stripped = trimmed.strip_prefix('/').unwrap_or(trimmed);
        let mut words = stripped.split_whitespace();
        let (Some(verb), Some("?"), None) = (words.next(), words.next(), words.next()) else {
            return false;
        };
        let Some(subverbs) = subverb_listing(verb) else {
            return false;
        };
        self.log(verb, format!("sub-verbs: {}", subverbs.join(", ")));
        true
    }

    fn remember_command(&mut self, trimmed: &str) {
        self.command_history.push(trimmed.to_string());
        if self.command_history.len() > COMMAND_HISTORY_CAP {
            let overflow = self.command_history.len() - COMMAND_HISTORY_CAP;
            self.command_history.drain(0..overflow);
        }
        self.persist_command_history();
    }

    fn handle_editor_local_command(&mut self, trimmed: &str) -> bool {
        if self.handle_prompt_editor_local_command(trimmed) {
            return true;
        }
        self.handle_tune_local_command(trimmed)
    }

    fn handle_prompt_editor_local_command(&mut self, trimmed: &str) -> bool {
        if !matches!(self.shell_view, ShellView::PromptsEditor)
            || trimmed.starts_with('/')
            || !self.is_bare_prompt_verb(trimmed)
        {
            return false;
        }
        self.handle_prompt_verb(trimmed);
        true
    }

    fn handle_tune_local_command(&mut self, trimmed: &str) -> bool {
        if !matches!(self.shell_view, ShellView::Tune)
            || trimmed.starts_with('/')
            || !self.is_bare_tune_verb(trimmed)
        {
            return false;
        }
        self.handle_tune_verb(trimmed);
        true
    }

    pub(crate) fn is_bare_prompt_verb(&self, raw: &str) -> bool {
        let head = raw.split_whitespace().next().unwrap_or("");
        matches!(head, "edit" | "show" | "diff" | "reset" | "set" | "list")
    }

    pub(crate) fn is_bare_tune_verb(&self, raw: &str) -> bool {
        let head = raw.split_whitespace().next().unwrap_or("");
        matches!(head, "show" | "set" | "reset")
    }

    fn discard_stashed_input_after_view_change(&mut self, previous_view: &ShellView) {
        if &self.shell_view != previous_view {
            self.last_cleared_input = None;
        }
    }
}

pub(crate) fn handle_home_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Home = command else {
        return false;
    };
    app.focused_module = None;
    app.catalog_expanded = false;
    app.shell_view = ShellView::Home;
    app.log("home", "showing Kuzushi cockpit");
    true
}

pub(crate) fn handle_help_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Help = command else {
        return false;
    };
    app.shell_view = ShellView::Help;
    app.help_scroll = 0;
    app.log("help", compact_help_summary());
    true
}

pub(crate) fn handle_back_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Back = command else {
        return false;
    };
    app.go_back();
    true
}

pub(crate) fn handle_cancel_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Cancel = command else {
        return false;
    };
    if !app.request_active_abort() {
        app.log("cancel", "no active scan/tool/agent to cancel");
    }
    true
}

pub(crate) fn handle_modules_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Modules = command else {
        return false;
    };
    app.shell_view = ShellView::Catalog;
    app.catalog_expanded = true;
    app.modules_scroll = 0;
    let count = app.registry.modules().count();
    app.log(
        "module",
        format!(
            "showing {count} {}",
            if count == 1 { "module" } else { "modules" }
        ),
    );
    true
}

pub(crate) fn handle_recommend_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Recommend = command else {
        return false;
    };
    app.shell_view = ShellView::Recommend;
    app.log("recommend", "latest module recommendations");
    true
}

pub(crate) fn handle_tools_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Tools = command else {
        return false;
    };
    app.shell_view = ShellView::Tools;
    app.tools_scroll = 0;
    let count = app.registry.tools().count();
    app.log(
        "tool",
        format!(
            "showing {count} {}",
            if count == 1 { "tool" } else { "tools" }
        ),
    );
    true
}

pub(crate) fn handle_workbench_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Workbench(pane) = command else {
        return false;
    };
    app.open_workbench(*pane);
    true
}

pub(crate) fn handle_findings_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    match command {
        ShellCommand::Findings => {
            app.show_findings();
            true
        }
        ShellCommand::FindingsFilter(expression) => {
            app.shell_view = ShellView::Workbench;
            app.workbench_focus = crate::app::WorkbenchPane::Findings;
            app.refresh_findings_filtered(expression);
            true
        }
        _ => false,
    }
}

pub(crate) fn handle_pwn_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Pwn(command) = command else {
        return false;
    };
    app.handle_pwn_command(command);
    true
}

pub(crate) fn handle_project_model_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::ProjectModel = command else {
        return false;
    };
    app.shell_view = ShellView::ProjectModel;
    app.scroll_offset = 0;
    app.log("project", "showing project model aggregate");
    true
}

pub(crate) fn handle_strategy_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Strategy(command) = command else {
        return false;
    };
    app.open_strategy_queue();
    app.apply_strategy_command(command);
    true
}

impl ShellApp {
    fn open_strategy_queue(&mut self) {
        self.shell_view = ShellView::StrategyQueue;
        self.scroll_offset = 0;
    }

    fn apply_strategy_command(&mut self, command: &StrategyCommand) {
        match command {
            StrategyCommand::Show => self.log("strategy", "showing strategy queue"),
            StrategyCommand::Approve(id) => self.update_strategy_proposal_status(
                id,
                kuzushi_core::StrategyProposalStatus::Approved,
                "approved",
            ),
            StrategyCommand::Reject(id) => self.update_strategy_proposal_status(
                id,
                kuzushi_core::StrategyProposalStatus::Rejected,
                "rejected",
            ),
            StrategyCommand::Correct {
                id,
                to_strategy,
                reason,
                scope,
            } => {
                self.record_strategy_correction_command(id, to_strategy, reason.as_deref(), *scope)
            }
            StrategyCommand::Unsupported(raw) => self.log_unknown_strategy_command(raw),
        }
    }

    fn log_unknown_strategy_command(&mut self, raw: &str) {
        self.log(
            "strategy",
            format!(
                "unknown strategy command: {raw}; try strategy approve <id> or strategy correct <id> <strategy>"
            ),
        );
    }

    fn update_strategy_proposal_status(
        &mut self,
        id: &str,
        status: kuzushi_core::StrategyProposalStatus,
        label: &str,
    ) {
        let Some(workspace) = self.strategy_workspace("updating") else {
            return;
        };
        match kuzushi_core::set_strategy_proposal_status(&workspace, id, status) {
            Ok(true) => self.log("strategy", format!("{label} {id}")),
            Ok(false) => self.log("strategy", format!("no strategy proposal named {id}")),
            Err(error) => self.log("strategy", format!("could not update {id}: {error}")),
        }
    }

    fn record_strategy_correction_command(
        &mut self,
        id: &str,
        to_strategy: &str,
        reason: Option<&str>,
        scope: StrategyCorrectionCommandScope,
    ) {
        let Some(workspace) = self.strategy_workspace("correcting") else {
            return;
        };
        let Some(proposal) = self.strategy_proposal(&workspace, id) else {
            return;
        };
        let correction = self.strategy_correction(&proposal, to_strategy, reason, scope);
        self.record_strategy_correction_result(&workspace, id, &correction);
    }

    fn strategy_workspace(&mut self, action: &str) -> Option<kuzushi_core::WorkspaceTarget> {
        let Some(target) = self.target.as_deref() else {
            self.log(
                "strategy",
                format!("select a target before {action} the strategy queue"),
            );
            return None;
        };
        match kuzushi_core::WorkspaceTarget::new(target) {
            Ok(workspace) => Some(workspace),
            Err(error) => {
                self.log("strategy", format!("target unavailable: {error}"));
                None
            }
        }
    }

    fn strategy_proposal(
        &mut self,
        workspace: &kuzushi_core::WorkspaceTarget,
        id: &str,
    ) -> Option<kuzushi_core::StrategyProposal> {
        let found = kuzushi_core::load_strategy_queue(workspace)
            .ok()?
            .into_iter()
            .find(|proposal| proposal.id == id);
        if found.is_none() {
            self.log("strategy", format!("no strategy proposal named {id}"));
        }
        found
    }

    fn strategy_correction(
        &self,
        proposal: &kuzushi_core::StrategyProposal,
        to_strategy: &str,
        reason: Option<&str>,
        scope: StrategyCorrectionCommandScope,
    ) -> kuzushi_core::StrategyCorrection {
        let correction_scope = strategy_correction_scope(scope);
        kuzushi_core::StrategyCorrection::new(
            proposal.phase,
            Some(proposal.id.clone()),
            proposal.effective_strategy().to_string(),
            to_strategy.trim().to_string(),
            correction_scope,
            self.strategy_correction_run_id(proposal, correction_scope),
            strategy_correction_reason(reason),
            "operator",
        )
    }

    fn strategy_correction_run_id(
        &self,
        proposal: &kuzushi_core::StrategyProposal,
        scope: kuzushi_core::StrategyCorrectionScope,
    ) -> Option<String> {
        (scope == kuzushi_core::StrategyCorrectionScope::Run)
            .then(|| {
                proposal
                    .source_run_id
                    .clone()
                    .or_else(|| self.active_strategy_run_id())
            })
            .flatten()
    }

    fn record_strategy_correction_result(
        &mut self,
        workspace: &kuzushi_core::WorkspaceTarget,
        id: &str,
        correction: &kuzushi_core::StrategyCorrection,
    ) {
        match kuzushi_core::record_strategy_correction(workspace, correction) {
            Ok(()) => self.log_strategy_correction(id, correction),
            Err(error) => self.log("strategy", format!("could not correct {id}: {error}")),
        }
    }

    fn log_strategy_correction(&mut self, id: &str, correction: &kuzushi_core::StrategyCorrection) {
        self.log(
            "strategy",
            format!(
                "corrected {id}: {} -> {} ({})",
                correction.from_strategy,
                correction.to_strategy,
                correction.scope.label()
            ),
        );
    }

    fn active_strategy_run_id(&self) -> Option<String> {
        self.tool_run_id
            .clone()
            .or_else(|| self.scan.as_ref().and_then(|scan| scan.run_id.clone()))
            .or_else(|| {
                self.activity
                    .as_ref()
                    .map(|activity| activity.run_id.clone())
            })
    }
}

fn strategy_correction_scope(
    scope: StrategyCorrectionCommandScope,
) -> kuzushi_core::StrategyCorrectionScope {
    match scope {
        StrategyCorrectionCommandScope::Run => kuzushi_core::StrategyCorrectionScope::Run,
        StrategyCorrectionCommandScope::Workspace => {
            kuzushi_core::StrategyCorrectionScope::Workspace
        }
    }
}

fn strategy_correction_reason(reason: Option<&str>) -> &str {
    reason
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("operator correction from Strategy Queue")
}

pub(crate) fn handle_open_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Open(id) = command else {
        return false;
    };
    app.open_finding(id);
    true
}

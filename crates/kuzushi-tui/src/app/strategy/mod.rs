use super::*;

impl ShellApp {
    pub(crate) fn open_strategy_queue(&mut self) {
        self.shell_view = ShellView::StrategyQueue;
        self.router.default_scroll_mut().reset();
    }

    pub(crate) fn reduce_strategy_command(
        &mut self,
        command: &StrategyCommand,
    ) -> Vec<ShellEffect> {
        self.open_strategy_queue();
        match command {
            StrategyCommand::Show => {
                self.log("strategy", "showing strategy queue");
                Vec::new()
            }
            StrategyCommand::Approve(id) => self.strategy_status_update_effects(
                id,
                kuzushi_core::StrategyProposalStatus::Approved,
                "approved",
            ),
            StrategyCommand::Reject(id) => self.strategy_status_update_effects(
                id,
                kuzushi_core::StrategyProposalStatus::Rejected,
                "rejected",
            ),
            StrategyCommand::Fire => self.strategy_fire_effects(),
            StrategyCommand::Correct {
                id,
                to_strategy,
                reason,
                scope,
            } => self.strategy_correction_effects(id, to_strategy, reason, *scope),
            StrategyCommand::Unsupported(raw) => {
                self.log_unknown_strategy_command(raw);
                Vec::new()
            }
        }
    }

    fn strategy_status_update_effects(
        &self,
        id: &str,
        status: kuzushi_core::StrategyProposalStatus,
        label: &'static str,
    ) -> Vec<ShellEffect> {
        vec![ShellEffect::UpdateStrategyProposalStatus(
            StrategyProposalStatusUpdate {
                target: self.target_owned(),
                id: id.to_string(),
                status,
                label,
            },
        )]
    }

    fn strategy_fire_effects(&self) -> Vec<ShellEffect> {
        vec![ShellEffect::FireNextApprovedStrategy(StrategyFireNext {
            target: self.target_owned(),
        })]
    }

    fn strategy_correction_effects(
        &self,
        id: &str,
        to_strategy: &str,
        reason: &Option<String>,
        scope: StrategyCorrectionCommandScope,
    ) -> Vec<ShellEffect> {
        vec![ShellEffect::RecordStrategyCorrection(
            StrategyCorrectionRecord {
                target: self.target_owned(),
                id: id.to_string(),
                to_strategy: to_strategy.to_string(),
                reason: reason.clone(),
                scope,
                active_run_id: self.active_strategy_run_id(),
            },
        )]
    }

    fn log_unknown_strategy_command(&mut self, raw: &str) {
        self.log(
            "strategy",
            format!(
                "unknown strategy command: {raw}; try strategy approve <id> or strategy correct <id> <strategy>"
            ),
        );
    }

    pub(super) fn fire_next_approved_strategy_effect(
        &mut self,
        fire: StrategyFireNext,
    ) -> Vec<ShellEffect> {
        let Some(workspace) = self.strategy_workspace_from_target(fire.target, "running") else {
            return Vec::new();
        };
        let Some((mut proposals, index, proposal)) = self.next_strategy_to_run(&workspace) else {
            return Vec::new();
        };
        if self.strategy_exceeds_budget(&proposal) {
            return Vec::new();
        }
        if !self.mark_strategy_running(&workspace, &mut proposals, index) {
            return Vec::new();
        }
        self.reduce_strategy_proposal_run(proposal)
    }

    fn next_strategy_to_run(
        &mut self,
        workspace: &kuzushi_core::WorkspaceTarget,
    ) -> Option<(
        Vec<kuzushi_core::StrategyProposal>,
        usize,
        kuzushi_core::StrategyProposal,
    )> {
        let proposals = self.load_strategy_queue_for_run(workspace)?;
        let Some(index) = proposals.iter().position(approved_runnable_strategy) else {
            self.log(
                "strategy",
                "no approved runnable strategy proposal; use `strategy keep <id>` first",
            );
            return None;
        };
        let proposal = proposals[index].clone();
        Some((proposals, index, proposal))
    }

    fn load_strategy_queue_for_run(
        &mut self,
        workspace: &kuzushi_core::WorkspaceTarget,
    ) -> Option<Vec<kuzushi_core::StrategyProposal>> {
        match kuzushi_core::load_strategy_queue(workspace) {
            Ok(proposals) => Some(proposals),
            Err(error) => {
                self.log(
                    "strategy",
                    format!("could not read strategy queue: {error}"),
                );
                None
            }
        }
    }

    fn mark_strategy_running(
        &mut self,
        workspace: &kuzushi_core::WorkspaceTarget,
        proposals: &mut [kuzushi_core::StrategyProposal],
        index: usize,
    ) -> bool {
        proposals[index].mark_running();
        if let Err(error) = kuzushi_core::save_strategy_queue(workspace, proposals) {
            self.log(
                "strategy",
                format!("could not mark strategy running: {error}"),
            );
            return false;
        }
        self.workbench_cache
            .borrow_mut()
            .invalidate_strategy_queue();
        true
    }

    fn reduce_strategy_proposal_run(
        &mut self,
        proposal: kuzushi_core::StrategyProposal,
    ) -> Vec<ShellEffect> {
        let tool = proposal.tool.clone().expect("runnable strategy has a tool");
        self.log("strategy", format!("firing {} via {tool}", proposal.id));
        self.reduce_run_tool(
            Some(tool),
            proposal.next_input.map(|input| input.to_string()),
        )
    }

    fn strategy_exceeds_budget(&mut self, proposal: &kuzushi_core::StrategyProposal) -> bool {
        let Some(cap) = self.session().session_budget_usd() else {
            return false;
        };
        let estimated = proposal
            .approved_cost_usd
            .or(proposal.expected_cost_usd)
            .unwrap_or(0.0)
            .max(0.0);
        let remaining = self.session().remaining_budget_usd().unwrap_or(cap);
        if estimated <= remaining {
            return false;
        }
        self.log(
            "strategy",
            format!(
                "proposal {} estimates ${estimated:.4}, above remaining session budget ${remaining:.4}",
                proposal.id
            ),
        );
        true
    }

    pub(super) fn update_strategy_proposal_status_effect(
        &mut self,
        update: StrategyProposalStatusUpdate,
    ) -> Vec<ShellEffect> {
        let Some(workspace) = self.strategy_workspace_from_target(update.target, "updating") else {
            return Vec::new();
        };
        match kuzushi_core::set_strategy_proposal_status(&workspace, &update.id, update.status) {
            Ok(true) => {
                self.workbench_cache
                    .borrow_mut()
                    .invalidate_strategy_queue();
                self.log("strategy", format!("{} {}", update.label, update.id));
            }
            Ok(false) => self.log(
                "strategy",
                format!("no strategy proposal named {}", update.id),
            ),
            Err(error) => self.log(
                "strategy",
                format!("could not update {}: {error}", update.id),
            ),
        }
        Vec::new()
    }

    pub(super) fn record_strategy_correction_effect(
        &mut self,
        record: StrategyCorrectionRecord,
    ) -> Vec<ShellEffect> {
        let StrategyCorrectionRecord {
            target,
            id,
            to_strategy,
            reason,
            scope,
            active_run_id,
        } = record;
        let Some(workspace) = self.strategy_workspace_from_target(target, "correcting") else {
            return Vec::new();
        };
        let Some(proposal) = self.strategy_proposal(&workspace, &id) else {
            return Vec::new();
        };
        let correction = self.strategy_correction(
            &proposal,
            &to_strategy,
            reason.as_deref(),
            scope,
            active_run_id,
        );
        self.record_strategy_correction_result(&workspace, &id, &correction);
        Vec::new()
    }

    fn strategy_workspace_from_target(
        &mut self,
        target: Option<std::path::PathBuf>,
        action: &str,
    ) -> Option<kuzushi_core::WorkspaceTarget> {
        let Some(target) = target else {
            self.log(
                "strategy",
                format!("select a target before {action} the strategy queue"),
            );
            return None;
        };
        match kuzushi_core::WorkspaceTarget::new(&target) {
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
        let proposals = match kuzushi_core::load_strategy_queue(workspace) {
            Ok(proposals) => proposals,
            Err(error) => {
                self.log(
                    "strategy",
                    format!("could not read strategy queue: {error}"),
                );
                return None;
            }
        };
        let found = proposals.into_iter().find(|proposal| proposal.id == id);
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
        active_run_id: Option<String>,
    ) -> kuzushi_core::StrategyCorrection {
        let correction_scope = strategy_correction_scope(scope);
        kuzushi_core::StrategyCorrection::new_at(
            unix_time_ms(),
            proposal.phase,
            Some(proposal.id.clone()),
            proposal.effective_strategy().to_string(),
            to_strategy.trim().to_string(),
            correction_scope,
            strategy_correction_run_id(proposal, correction_scope, active_run_id),
            strategy_correction_reason(reason),
            "operator",
        )
    }

    fn record_strategy_correction_result(
        &mut self,
        workspace: &kuzushi_core::WorkspaceTarget,
        id: &str,
        correction: &kuzushi_core::StrategyCorrection,
    ) {
        match kuzushi_core::record_and_apply_strategy_correction(workspace, correction) {
            Ok(()) => {
                self.workbench_cache
                    .borrow_mut()
                    .invalidate_strategy_queue();
                self.log_strategy_correction(id, correction);
            }
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
        self.active_tool_run_id()
            .map(str::to_string)
            .or_else(|| self.scan().and_then(|scan| scan.run_id.clone()))
            .or_else(|| self.activity().map(|activity| activity.run_id.clone()))
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

fn strategy_correction_run_id(
    proposal: &kuzushi_core::StrategyProposal,
    scope: kuzushi_core::StrategyCorrectionScope,
    active_run_id: Option<String>,
) -> Option<String> {
    (scope == kuzushi_core::StrategyCorrectionScope::Run)
        .then(|| proposal.source_run_id.clone().or(active_run_id))
        .flatten()
}

fn approved_runnable_strategy(proposal: &kuzushi_core::StrategyProposal) -> bool {
    proposal.status == kuzushi_core::StrategyProposalStatus::Approved
        && proposal
            .tool
            .as_deref()
            .is_some_and(|tool| !tool.trim().is_empty())
        && proposal.preflight.status != kuzushi_core::StrategyPreflightStatus::Blocked
}

use super::*;

impl ShellApp {
    pub(crate) fn open_strategy_queue(&mut self) {
        self.shell_view = ShellView::StrategyQueue;
        self.scroll_offset = 0;
    }

    pub(crate) fn apply_strategy_command(&mut self, command: &StrategyCommand) {
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
            Ok(true) => {
                self.workbench_cache
                    .borrow_mut()
                    .invalidate_strategy_queue();
                self.log("strategy", format!("{label} {id}"));
            }
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
    ) -> kuzushi_core::StrategyCorrection {
        let correction_scope = strategy_correction_scope(scope);
        kuzushi_core::StrategyCorrection::new_at(
            unix_time_ms(),
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

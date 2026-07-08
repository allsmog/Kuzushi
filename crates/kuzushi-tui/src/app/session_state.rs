use super::TargetCandidateScope;
use kuzushi_core::{ModuleRegistry, ToolOptionStore, V2Config};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(crate) struct SessionState {
    config: V2Config,
    registry: ModuleRegistry,
    option_store: ToolOptionStore,
    target: Option<PathBuf>,
    active_scope: Option<TargetCandidateScope>,
    session_cost_usd: f64,
    last_tool_cost_usd: Option<f64>,
    session_budget_usd: Option<f64>,
    trusted_workflow_auto_accept: bool,
    thinking_level: Option<String>,
}

impl SessionState {
    pub(crate) fn new(
        config: V2Config,
        registry: ModuleRegistry,
        option_store: ToolOptionStore,
        target: Option<PathBuf>,
        session_budget_usd: Option<f64>,
        trusted_workflow_auto_accept: bool,
    ) -> Self {
        Self {
            config,
            registry,
            option_store,
            target,
            active_scope: None,
            session_cost_usd: 0.0,
            last_tool_cost_usd: None,
            session_budget_usd,
            trusted_workflow_auto_accept,
            thinking_level: None,
        }
    }

    pub(crate) fn config(&self) -> &V2Config {
        &self.config
    }

    pub(crate) fn config_mut(&mut self) -> &mut V2Config {
        &mut self.config
    }

    pub(crate) fn registry(&self) -> &ModuleRegistry {
        &self.registry
    }

    pub(crate) fn registry_mut(&mut self) -> &mut ModuleRegistry {
        &mut self.registry
    }

    pub(crate) fn option_store(&self) -> &ToolOptionStore {
        &self.option_store
    }

    pub(crate) fn option_store_mut(&mut self) -> &mut ToolOptionStore {
        &mut self.option_store
    }

    pub(crate) fn set_option_store(&mut self, option_store: ToolOptionStore) {
        self.option_store = option_store;
    }

    pub(crate) fn target(&self) -> Option<&Path> {
        self.target.as_deref()
    }

    pub(crate) fn target_path_buf(&self) -> Option<&PathBuf> {
        self.target.as_ref()
    }

    pub(crate) fn target_owned(&self) -> Option<PathBuf> {
        self.target.clone()
    }

    pub(crate) fn set_target(&mut self, target: Option<PathBuf>) {
        self.target = target;
    }

    pub(crate) fn active_scope(&self) -> Option<&TargetCandidateScope> {
        self.active_scope.as_ref()
    }

    pub(crate) fn set_active_scope(&mut self, scope: Option<TargetCandidateScope>) {
        self.active_scope = scope;
    }

    pub(crate) fn session_cost_usd(&self) -> f64 {
        self.session_cost_usd
    }

    pub(crate) fn last_tool_cost_usd(&self) -> Option<f64> {
        self.last_tool_cost_usd
    }

    pub(crate) fn session_budget_usd(&self) -> Option<f64> {
        self.session_budget_usd
    }

    pub(crate) fn set_session_budget_usd(&mut self, budget: Option<f64>) {
        self.session_budget_usd = budget;
    }

    pub(crate) fn trusted_workflow_auto_accept(&self) -> bool {
        self.trusted_workflow_auto_accept
    }

    #[cfg(test)]
    pub(crate) fn set_trusted_workflow_auto_accept(&mut self, enabled: bool) {
        self.trusted_workflow_auto_accept = enabled;
    }

    pub(crate) fn thinking_level(&self) -> Option<&str> {
        self.thinking_level.as_deref()
    }

    pub(crate) fn thinking_level_owned(&self) -> Option<String> {
        self.thinking_level.clone()
    }

    pub(crate) fn set_thinking_level(&mut self, thinking_level: Option<String>) {
        self.thinking_level = thinking_level;
    }

    pub(crate) fn record_cost(&mut self, cost_usd: f64) {
        self.last_tool_cost_usd = Some(cost_usd);
        self.session_cost_usd += cost_usd;
    }

    #[cfg(test)]
    pub(crate) fn set_session_cost_usd_for_test(&mut self, cost: f64) {
        self.session_cost_usd = cost;
    }

    #[cfg(test)]
    pub(crate) fn set_last_tool_cost_usd_for_test(&mut self, cost: Option<f64>) {
        self.last_tool_cost_usd = cost;
    }

    pub(crate) fn remaining_budget_usd(&self) -> Option<f64> {
        self.session_budget_usd
            .map(|cap| (cap - self.session_cost_usd).max(0.0))
    }
}

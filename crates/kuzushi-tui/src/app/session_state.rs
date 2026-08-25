use super::{
    ActiveTargetFactsState, ShellSessionTranscript, StampedTargetCandidateFacts, SteerQueue,
    TargetCandidateFacts, TargetCandidateScope,
};
use kuzushi_core::runtime::{RuntimeCost, RuntimeCostReport};
use kuzushi_core::{ModuleRegistry, NestedProjectScopeTree, ToolOptionStore, V2Config};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(crate) struct SessionState {
    config: V2Config,
    registry: ModuleRegistry,
    option_store: ToolOptionStore,
    target: Option<PathBuf>,
    active_target_facts: ActiveTargetFactsState,
    active_scope: Option<TargetCandidateScope>,
    /// The last scope tree announced as ready, kept here — not in the
    /// invalidation-driven workbench cache — so external state churn can
    /// never defeat the "an unchanged tree is announced once" dedup.
    announced_scope_tree: Option<(PathBuf, NestedProjectScopeTree)>,
    session_cost: RuntimeCostReport,
    unscoped_cost: RuntimeCostReport,
    run_costs: BTreeMap<String, RunCostEntry>,
    last_tool_cost: Option<RuntimeCostReport>,
    cost_accounting_error: Option<String>,
    session_budget_usd: Option<f64>,
    trusted_workflow_auto_accept: bool,
    thinking_level: Option<String>,
    /// Providers whose API key was accepted during this process. This stores
    /// readiness only; key material stays in the `SetSessionEnv` effect.
    session_api_key_providers: BTreeSet<String>,
    steer_queue: SteerQueue,
    transcript: Option<ShellSessionTranscript>,
    transcript_start_warning: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct RunCostEntry {
    report: RuntimeCostReport,
    provider_call_possible: bool,
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
            active_target_facts: ActiveTargetFactsState::default(),
            active_scope: None,
            announced_scope_tree: None,
            session_cost: RuntimeCostReport::known(RuntimeCost::ZERO),
            unscoped_cost: RuntimeCostReport::known(RuntimeCost::ZERO),
            run_costs: BTreeMap::new(),
            last_tool_cost: None,
            cost_accounting_error: None,
            session_budget_usd,
            trusted_workflow_auto_accept,
            thinking_level: None,
            session_api_key_providers: BTreeSet::new(),
            steer_queue: SteerQueue::default(),
            transcript: None,
            transcript_start_warning: None,
        }
    }

    pub(crate) fn attach_transcript(&mut self, transcript: ShellSessionTranscript) {
        self.transcript = Some(transcript);
        self.transcript_start_warning = None;
    }

    pub(crate) fn transcript(&self) -> Option<&ShellSessionTranscript> {
        self.transcript.as_ref()
    }

    pub(crate) fn transcript_mut(&mut self) -> Option<&mut ShellSessionTranscript> {
        self.transcript.as_mut()
    }

    pub(crate) fn take_transcript(&mut self) -> Option<ShellSessionTranscript> {
        self.transcript.take()
    }

    pub(crate) fn set_transcript_start_warning(&mut self, warning: String) {
        self.transcript_start_warning = Some(warning);
    }

    pub(crate) fn transcript_start_warning(&self) -> Option<&str> {
        self.transcript_start_warning.as_deref()
    }

    pub(crate) fn steer_queue(&self) -> &SteerQueue {
        &self.steer_queue
    }

    pub(crate) fn steer_queue_mut(&mut self) -> &mut SteerQueue {
        &mut self.steer_queue
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

    pub(crate) fn begin_active_target_facts(&mut self, path: PathBuf, generation: u64) {
        self.active_target_facts.begin(path, generation);
    }

    pub(crate) fn apply_active_target_facts(&mut self, facts: StampedTargetCandidateFacts) -> bool {
        self.active_target_facts.apply(facts)
    }

    pub(crate) fn active_target_facts(&self) -> Option<&TargetCandidateFacts> {
        self.active_target_facts.facts()
    }

    pub(crate) fn active_target_facts_loading(&self) -> bool {
        self.active_target_facts.loading()
    }

    #[cfg(test)]
    pub(crate) fn active_target_facts_path(&self) -> Option<&Path> {
        self.active_target_facts.path()
    }

    pub(crate) fn active_scope(&self) -> Option<&TargetCandidateScope> {
        self.active_scope.as_ref()
    }

    pub(crate) fn set_active_scope(&mut self, scope: Option<TargetCandidateScope>) {
        self.active_scope = scope;
    }

    pub(crate) fn scope_tree_already_announced(
        &self,
        root: &Path,
        tree: &NestedProjectScopeTree,
    ) -> bool {
        self.announced_scope_tree
            .as_ref()
            .is_some_and(|(announced_root, announced)| announced_root == root && announced == tree)
    }

    pub(crate) fn record_scope_tree_announcement(
        &mut self,
        root: PathBuf,
        tree: NestedProjectScopeTree,
    ) {
        self.announced_scope_tree = Some((root, tree));
    }

    pub(crate) fn session_cost_usd(&self) -> f64 {
        self.session_cost.observed_usd()
    }

    pub(crate) fn session_cost_report(&self) -> RuntimeCostReport {
        self.session_cost
    }

    pub(crate) fn last_tool_cost_usd(&self) -> Option<f64> {
        self.last_tool_cost
            .and_then(RuntimeCostReport::observed_usd_if_available)
    }

    pub(crate) fn last_tool_cost_report(&self) -> Option<RuntimeCostReport> {
        self.last_tool_cost
    }

    pub(crate) fn cost_accounting_error(&self) -> Option<&str> {
        self.cost_accounting_error.as_deref()
    }

    pub(crate) fn cost_accounting_is_complete(&self) -> bool {
        self.cost_accounting_error.is_none() && self.session_cost.is_complete()
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

    pub(crate) fn mark_session_api_key_ready(&mut self, provider: &str) {
        self.session_api_key_providers.insert(provider.to_string());
    }

    pub(crate) fn clear_session_api_key_ready(&mut self, provider: &str) {
        self.session_api_key_providers.remove(provider);
    }

    pub(crate) fn session_api_key_ready(&self, provider: &str) -> bool {
        self.session_api_key_providers.contains(provider)
    }

    pub(crate) fn record_cost(&mut self, cost_usd: f64) -> anyhow::Result<()> {
        let cost = RuntimeCost::from_usd(cost_usd, "shell session cost")?;
        self.record_cost_report(RuntimeCostReport::known(cost))
    }

    pub(crate) fn record_cost_report(&mut self, cost: RuntimeCostReport) -> anyhow::Result<()> {
        let unscoped = self
            .unscoped_cost
            .checked_add(cost, "shell unscoped cost total")?;
        let total = self.total_with_unscoped(unscoped)?;
        self.last_tool_cost = Some(cost);
        self.unscoped_cost = unscoped;
        self.session_cost = total;
        Ok(())
    }

    pub(crate) fn begin_run_cost_tracking(&mut self, run_id: &str, provider_call_possible: bool) {
        self.run_costs
            .entry(run_id.to_string())
            .and_modify(|entry| entry.provider_call_possible |= provider_call_possible)
            .or_insert(RunCostEntry {
                report: RuntimeCostReport::known(RuntimeCost::ZERO),
                provider_call_possible,
            });
    }

    pub(crate) fn settle_run_cost_report(
        &mut self,
        run_id: &str,
        reported: RuntimeCostReport,
    ) -> anyhow::Result<RuntimeCostReport> {
        if !self.run_costs.contains_key(run_id) {
            self.begin_run_cost_tracking(run_id, reported.is_unavailable());
        }
        let current = self.run_costs[run_id];
        let report = normalized_terminal_report(current, reported)?;
        self.replace_run_report(run_id, report, true)
    }

    fn replace_run_report(
        &mut self,
        run_id: &str,
        report: RuntimeCostReport,
        terminal: bool,
    ) -> anyhow::Result<RuntimeCostReport> {
        let total = self.total_with_run_report(run_id, report)?;
        self.run_costs
            .get_mut(run_id)
            .expect("run cost entry")
            .report = report;
        self.session_cost = total;
        if terminal {
            self.last_tool_cost = Some(report);
        }
        Ok(report)
    }

    fn total_with_unscoped(
        &self,
        unscoped: RuntimeCostReport,
    ) -> anyhow::Result<RuntimeCostReport> {
        self.run_costs.values().try_fold(unscoped, |total, entry| {
            total.checked_add(entry.report, "shell session cost total")
        })
    }

    fn total_with_run_report(
        &self,
        run_id: &str,
        report: RuntimeCostReport,
    ) -> anyhow::Result<RuntimeCostReport> {
        self.run_costs
            .iter()
            .try_fold(self.unscoped_cost, |total, (id, entry)| {
                let cost = if id == run_id { report } else { entry.report };
                total.checked_add(cost, "shell session cost total")
            })
    }

    pub(crate) fn mark_cost_accounting_error(&mut self, error: impl Into<String>) {
        self.cost_accounting_error
            .get_or_insert_with(|| error.into());
    }

    #[cfg(test)]
    pub(crate) fn set_session_cost_usd_for_test(&mut self, cost: f64) {
        let report = RuntimeCostReport::known(
            RuntimeCost::from_usd(cost, "test session cost").expect("valid test session cost"),
        );
        self.session_cost = report;
        self.unscoped_cost = report;
        self.run_costs.clear();
        self.cost_accounting_error = None;
    }

    #[cfg(test)]
    pub(crate) fn set_last_tool_cost_usd_for_test(&mut self, cost: Option<f64>) {
        self.last_tool_cost = cost.map(|cost| {
            RuntimeCostReport::known(
                RuntimeCost::from_usd(cost, "test tool cost").expect("valid test tool cost"),
            )
        });
    }

    pub(crate) fn remaining_budget_usd(&self) -> Option<f64> {
        self.session_budget_usd.map(|cap| {
            if self.cost_accounting_is_complete() {
                (cap - self.session_cost_usd()).max(0.0)
            } else {
                0.0
            }
        })
    }
}

fn normalized_terminal_report(
    current: RunCostEntry,
    reported: RuntimeCostReport,
) -> anyhow::Result<RuntimeCostReport> {
    if !reported.is_unavailable() {
        anyhow::ensure!(
            !terminal_receipt_is_lower(current.report, reported),
            "terminal run cost ${:.12} is below live observed subtotal ${:.12}",
            reported.observed_usd(),
            current.report.observed_usd()
        );
        return Ok(reported);
    }
    if current.provider_call_possible {
        Ok(current.report.mark_incomplete())
    } else {
        Ok(current.report)
    }
}

fn terminal_receipt_is_lower(current: RuntimeCostReport, terminal: RuntimeCostReport) -> bool {
    let current_usd = current.observed_usd();
    let terminal_usd = terminal.observed_usd();
    let scale = current_usd.abs().max(terminal_usd.abs()).max(1.0);
    let tolerance = f64::EPSILON * scale * 8.0;
    current_usd > terminal_usd && current_usd - terminal_usd > tolerance
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_receipt_is_idempotent_without_double_counting() {
        let mut session = test_session();
        session.begin_run_cost_tracking("run-1", true);

        session.settle_run_cost_report("run-1", exact(0.3)).unwrap();
        session.settle_run_cost_report("run-1", exact(0.3)).unwrap();

        assert!((session.session_cost_usd() - 0.3).abs() < 1e-12);
        assert_eq!(session.last_tool_cost_usd(), Some(0.3));
    }

    #[test]
    fn unavailable_terminal_receipt_distinguishes_runtime_from_no_call_run() {
        let mut runtime = test_session();
        runtime.begin_run_cost_tracking("runtime", true);
        let unresolved = runtime
            .settle_run_cost_report("runtime", RuntimeCostReport::UNAVAILABLE)
            .unwrap();
        assert!(!unresolved.is_complete());
        assert!(!runtime.cost_accounting_is_complete());

        let mut deterministic = test_session();
        deterministic.begin_run_cost_tracking("deterministic", false);
        let zero = deterministic
            .settle_run_cost_report("deterministic", RuntimeCostReport::UNAVAILABLE)
            .unwrap();
        assert_eq!(zero.exact_usd(), Some(0.0));
        assert!(deterministic.cost_accounting_is_complete());
    }

    #[test]
    fn repeated_terminal_receipt_cannot_lower_settled_spend() {
        let mut session = test_session();
        session.begin_run_cost_tracking("run-1", true);
        session.settle_run_cost_report("run-1", exact(0.4)).unwrap();

        let error = session
            .settle_run_cost_report("run-1", exact(0.3))
            .unwrap_err();

        assert!(error.to_string().contains("below live observed subtotal"));
        assert!((session.session_cost_usd() - 0.4).abs() < f64::EPSILON);
    }

    #[test]
    fn mutation_survivor_active_target_facts_loading_forwards_pending_state() {
        let mut session = test_session();
        session.begin_active_target_facts(PathBuf::from("/tmp/target"), 1);

        assert!(session.active_target_facts_loading());
    }

    fn test_session() -> SessionState {
        SessionState::new(
            V2Config::default(),
            ModuleRegistry::with_v2_builtins(),
            ToolOptionStore::default(),
            None,
            None,
            false,
        )
    }

    fn exact(cost: f64) -> RuntimeCostReport {
        RuntimeCostReport::known(RuntimeCost::from_usd(cost, "test cost").unwrap())
    }
}

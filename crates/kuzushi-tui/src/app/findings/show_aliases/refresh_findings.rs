use super::*;
use anyhow::Context;
use kuzushi_core::findings::IdentityFoldPolicy;
use kuzushi_core::FindingListReport;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Whether one ledger finding was observed by any of `run_refs`.
///
/// A re-observed finding keeps the later run as its representative `scan_id`
/// while the earlier run stays in `sources`, so matching the representative
/// alone silently drops the finding from the earlier run that found it.
pub(crate) fn finding_observed_in_runs(finding: &Finding, run_refs: &BTreeSet<String>) -> bool {
    if finding
        .scan_id
        .as_ref()
        .is_some_and(|run_id| run_refs.contains(run_id))
    {
        return true;
    }
    finding.sources.iter().any(|source| {
        run_refs.contains(&source.first_scan_id) || run_refs.contains(&source.last_scan_id)
    })
}

impl ShellApp {
    /// Reload findings, then keep the advisory queue scores current for the
    /// generation just loaded. The reload is the only place the queue changes,
    /// so it is the one place scoring has to be re-requested.
    pub(crate) fn refresh_findings_effect(&mut self, refresh: FindingsRefresh) -> Vec<ShellEffect> {
        match refresh.filter {
            Some(expression) => self.refresh_findings_filtered(&expression),
            // `None` means reload the current projection. The explicit
            // `findings` command clears route state before issuing it.
            None => self.refresh_findings_preserving_active_filter(refresh.announce),
        }
        self.review_yield_queue_scoring_effects()
    }

    /// Reload findings without changing the operator's active projection.
    /// Call `refresh_findings` only when the caller explicitly wants the
    /// unfiltered ledger and has intentionally cleared the filter.
    pub(crate) fn refresh_findings_preserving_active_filter(&mut self, announce: bool) {
        let Some(expression) = self.active_findings_filter().clone() else {
            self.refresh_findings(announce);
            return;
        };
        self.refresh_findings_filtered(&expression);
    }

    pub(crate) fn refresh_findings(&mut self, announce: bool) {
        let operator_state = match self.identity_policy_operator_state_dir() {
            Ok(path) => path,
            Err(error) => {
                self.log_refresh_findings_error(error, announce);
                return;
            }
        };
        self.refresh_findings_with_operator_state(announce, &operator_state);
    }

    fn refresh_findings_with_operator_state(&mut self, announce: bool, operator_state: &Path) {
        let (store, policy) = match self.open_store_and_identity_policy(operator_state) {
            Ok(resolved) => resolved,
            Err(error) => {
                self.log_refresh_findings_error(error, announce);
                return;
            }
        };
        let filter = FindingListFilter::with_limit(FindingListFilter::MAX_LIMIT);
        let read_watermark = self.current_findings_projection_watermark(&store);
        match store.list_findings_filtered_with_identity_policy(&filter, policy) {
            Ok(report) => {
                self.replace_findings_from_store(&store, report, policy, announce, read_watermark)
            }
            Err(error) => self.log_refresh_findings_error(error.into(), announce),
        }
    }

    pub(crate) fn refresh_findings_filtered(&mut self, expression: &str) {
        let operator_state = match self.identity_policy_operator_state_dir() {
            Ok(path) => path,
            Err(error) => {
                self.log_refresh_findings_error(error, true);
                return;
            }
        };
        self.refresh_findings_filtered_with_operator_state(expression, &operator_state);
    }

    fn refresh_findings_filtered_with_operator_state(
        &mut self,
        expression: &str,
        operator_state: &Path,
    ) {
        let Some((filter, requested_limit)) = self.parsed_refresh_filter(expression) else {
            return;
        };
        let (store, policy) = match self.open_store_and_identity_policy(operator_state) {
            Ok(resolved) => resolved,
            Err(error) => {
                self.log_refresh_findings_error(error, true);
                return;
            }
        };
        let read_watermark = self.current_findings_projection_watermark(&store);
        match store.list_findings_filtered_with_identity_policy(&filter, policy) {
            Ok(report) => match self.filter_findings_by_provenance(report, &filter) {
                Ok(report) => {
                    let report = truncate_findings_report(report, requested_limit);
                    self.refresh_journey_ledger_counts_with_policy(&store, policy);
                    self.replace_filtered_findings(
                        &store,
                        report,
                        policy,
                        expression,
                        read_watermark,
                    );
                }
                Err(error) => self.log("error", format!("invalid findings filter: {error}")),
            },
            Err(error) => self.log_refresh_findings_error(error.into(), true),
        }
    }

    fn parsed_refresh_filter(&mut self, expression: &str) -> Option<(FindingListFilter, usize)> {
        let mut filter = match FindingListFilter::from_filter_expression(expression) {
            Ok(filter) => filter,
            Err(error) => {
                self.log("error", format!("invalid findings filter: {error}"));
                return None;
            }
        };
        let requested_limit = filter.limit;
        if filter.has_provenance_filter() {
            filter.limit = FindingListFilter::MAX_LIMIT;
        }
        Some((filter, requested_limit))
    }

    fn filter_findings_by_provenance(
        &self,
        report: FindingListReport,
        filter: &FindingListFilter,
    ) -> anyhow::Result<FindingListReport> {
        if !filter.has_provenance_filter() {
            return Ok(report);
        }
        let Some(target) = self.target_path_buf() else {
            anyhow::bail!("revision filters require an active target");
        };
        let runs = kuzushi_core::list_run_summaries(target)?
            .into_iter()
            .map(|summary| (summary.run_id.clone(), summary))
            .collect::<BTreeMap<_, _>>();
        let (findings, aliases): (Vec<_>, Vec<_>) = report
            .findings
            .into_iter()
            .zip(report.aliases)
            .filter(|(finding, _)| filter.matches_run_provenance(finding, &runs))
            .unzip();
        let count = findings.len();
        Ok(FindingListReport {
            review_decisions: report.review_decisions,
            count,
            findings,
            aliases,
        })
    }

    fn replace_findings_from_store(
        &mut self,
        store: &FindingStore,
        report: FindingListReport,
        policy: IdentityFoldPolicy,
        announce: bool,
        read_watermark: Option<u64>,
    ) {
        let FindingListReport {
            count,
            findings,
            aliases,
            ..
        } = report;
        let decisions = self.load_review_decisions_for_findings(store, &findings);
        let counts = self.journey_ledger_counts(store, policy, &findings, &decisions, count);
        self.domain_mut().set_finding_ledger_counts(counts);
        self.replace_findings(
            findings,
            aliases,
            policy,
            decisions,
            announce,
            count,
            read_watermark,
        );
    }

    pub(crate) fn refresh_journey_ledger_projection(&mut self) {
        let Ok(store) = self.open_store() else {
            return;
        };
        let policy = self.identity_fold_policy();
        self.refresh_journey_ledger_counts_with_policy(&store, policy);
    }

    fn refresh_journey_ledger_counts_with_policy(
        &mut self,
        store: &FindingStore,
        policy: IdentityFoldPolicy,
    ) {
        let filter = FindingListFilter::with_limit(FindingListFilter::MAX_LIMIT);
        let Ok(report) = store.list_findings_filtered_with_identity_policy(&filter, policy) else {
            return;
        };
        let decisions = self.load_review_decisions_for_findings(store, &report.findings);
        let counts =
            self.journey_ledger_counts(store, policy, &report.findings, &decisions, report.count);
        self.domain_mut().set_finding_ledger_counts(counts);
    }

    fn journey_ledger_counts(
        &mut self,
        store: &FindingStore,
        policy: IdentityFoldPolicy,
        fallback_findings: &[Finding],
        fallback_decisions: &[kuzushi_core::findings::ReviewDecisionRecord],
        fallback_total: usize,
    ) -> FindingLedgerCounts {
        match self.relevant_journey_findings(store, policy) {
            Ok(findings) => self.count_journey_findings(store, &findings, findings.len()),
            Err(error) => {
                self.log(
                    "error",
                    format!("could not load the relevant findings corpus: {error}"),
                );
                self.count_journey_findings_with_decisions(
                    store,
                    fallback_findings,
                    fallback_decisions,
                    fallback_total,
                )
            }
        }
    }

    fn relevant_journey_findings(
        &self,
        store: &FindingStore,
        policy: IdentityFoldPolicy,
    ) -> anyhow::Result<Vec<Finding>> {
        let mut findings = store.list_relevant_findings_with_identity_policy(policy)?;
        let Some(run_refs) = self.selected_current_scan_run_refs() else {
            return Ok(findings);
        };
        let run_refs = run_refs.into_iter().collect::<BTreeSet<_>>();
        findings.retain(|finding| finding_observed_in_runs(finding, &run_refs));
        Ok(findings)
    }

    fn selected_current_scan_run_refs(&self) -> Option<Vec<String>> {
        if !self
            .engagement
            .selected_attempt_completed_after(WorkflowPhase::Map, WorkflowPhase::Scan)
        {
            return None;
        }
        let attempt = self
            .engagement
            .selected_phase_attempt(WorkflowPhase::Scan)?;
        Some(attempt.completed.run_refs.clone())
    }

    fn count_journey_findings(
        &mut self,
        store: &FindingStore,
        findings: &[Finding],
        total: usize,
    ) -> FindingLedgerCounts {
        let decisions = self.load_review_decisions_for_findings(store, findings);
        self.count_journey_findings_with_decisions(store, findings, &decisions, total)
    }

    fn count_journey_findings_with_decisions(
        &mut self,
        store: &FindingStore,
        findings: &[Finding],
        decisions: &[kuzushi_core::findings::ReviewDecisionRecord],
        total: usize,
    ) -> FindingLedgerCounts {
        let mut counts = crate::ui_view_models::finding_ledger_counts(findings, decisions, total);
        crate::ui_view_models::attach_proof_deferral_counts(
            &mut counts,
            findings,
            decisions,
            &self.engagement,
        );
        self.refresh_remediation_projection(store, findings, decisions, &mut counts);
        counts
    }

    fn refresh_remediation_projection(
        &mut self,
        store: &FindingStore,
        findings: &[Finding],
        decisions: &[kuzushi_core::findings::ReviewDecisionRecord],
        counts: &mut FindingLedgerCounts,
    ) {
        let lifecycles = match store.list_patch_lifecycle_current() {
            Ok(lifecycles) => lifecycles,
            Err(error) => {
                self.domain_mut().set_patch_lifecycle_records(&[]);
                self.log(
                    "error",
                    format!("could not load remediation projection: {error}"),
                );
                return;
            }
        };
        crate::ui_view_models::attach_remediation_counts(counts, findings, decisions, &lifecycles);
        self.domain_mut().set_patch_lifecycle_records(&lifecycles);
    }

    fn replace_findings(
        &mut self,
        findings: Vec<Finding>,
        aliases: Vec<String>,
        policy: IdentityFoldPolicy,
        review_decisions: Vec<kuzushi_core::findings::ReviewDecisionRecord>,
        announce: bool,
        total_count: usize,
        read_watermark: Option<u64>,
    ) {
        let cursored_identity = crate::ui_view_models::visible_finding_at_cursor(self)
            .map(|(_, finding)| finding_generation_key(&finding));
        self.set_findings_projection(findings, aliases, policy);
        self.set_findings_total_count(total_count);
        self.set_findings_read_watermark(read_watermark);
        self.set_review_decisions(review_decisions);
        self.set_active_findings_filter(None);
        self.reselect_current_finding();
        self.sync_findings_cursor_to_selected();
        self.reanchor_cursor_to_cursored_identity(cursored_identity);
        // A reload invalidates a pending X-X bulk-defer confirmation: the
        // second press must defer exactly the set whose count the arm
        // message showed, so new data means re-arming with a fresh count.
        self.router
            .workbench_mut()
            .review_mut()
            .backlog_confirm_bulk = false;
        if announce {
            let count = self.findings().len();
            self.log("findings", findings_loaded_message(count, total_count));
        }
    }

    /// One-key decisions act on the CURSORED row, so a reload that reorders
    /// the projection must never swap a different finding under a stationary
    /// cursor. Re-anchor to the finding the operator was on, overriding the
    /// selected-finding sync (selection tracks the last OPENED finding, which
    /// may be rows away from where the operator is browsing). A vanished row
    /// (e.g. just decided in the backlog) keeps the clamped index so the
    /// cursor advances to the next row.
    fn reanchor_cursor_to_cursored_identity(&mut self, identity: Option<String>) {
        let Some(identity) = identity else {
            return;
        };
        let position = (0..crate::ui_view_models::visible_findings_len(self)).find(|index| {
            crate::ui_view_models::visible_finding_at_index(self, *index)
                .is_some_and(|(_, finding)| finding_generation_key(&finding) == identity)
        });
        if let Some(index) = position {
            self.router.findings_mut().set_cursor(index);
        }
    }

    fn replace_filtered_findings(
        &mut self,
        store: &FindingStore,
        report: FindingListReport,
        policy: IdentityFoldPolicy,
        expression: &str,
        read_watermark: Option<u64>,
    ) {
        let FindingListReport {
            count,
            findings,
            aliases,
            ..
        } = report;
        let decisions = self.load_review_decisions_for_findings(store, &findings);
        self.replace_findings(
            findings,
            aliases,
            policy,
            decisions,
            false,
            count,
            read_watermark,
        );
        self.set_active_findings_filter(Some(expression.to_string()));
        self.log(
            "findings",
            format!(
                "filter {expression:?}: loaded {} of {count} matching",
                self.findings().len()
            ),
        );
    }

    fn identity_policy_operator_state_dir(&self) -> anyhow::Result<std::path::PathBuf> {
        Ok(kuzushi_core::ConfigPaths::from_target(self.target())?.global_state_dir())
    }

    fn open_store_and_identity_policy(
        &mut self,
        operator_state: &Path,
    ) -> anyhow::Result<(FindingStore, IdentityFoldPolicy)> {
        let store = self.open_store()?;
        let target = self
            .target()
            .context("finding identity policy requires an active target")?;
        let values = self.option_store().effective_stored_values("sast:scan");
        let requested = values.get("identityFold").and_then(|value| value.as_str());
        let defaults = kuzushi_core::findings::resolve_identity_policy_defaults(
            operator_state,
            target,
            requested,
            None,
        )?;
        let policy = IdentityFoldPolicy::parse(Some(&defaults.identity_fold))?;
        Ok((store, policy))
    }

    fn current_findings_projection_watermark(&mut self, store: &FindingStore) -> Option<u64> {
        match store.projection_meta() {
            Ok(meta) => Some(meta.applied_seq),
            Err(error) => {
                self.log(
                    "error",
                    with_next_step(
                        format!("could not read findings projection watermark: {error}"),
                        "workspace status",
                    ),
                );
                None
            }
        }
    }

    fn load_review_decisions_for_findings(
        &mut self,
        store: &FindingStore,
        findings: &[Finding],
    ) -> Vec<kuzushi_core::findings::ReviewDecisionRecord> {
        match review_decisions_for_findings(store, findings) {
            Ok(decisions) => decisions,
            Err(error) => {
                self.log(
                    "error",
                    with_next_step(
                        format!("could not load review decisions: {error}"),
                        "workspace status",
                    ),
                );
                Vec::new()
            }
        }
    }

    fn reselect_current_finding(&mut self) {
        let Some(selected_fingerprint) = self
            .selected_finding()
            .as_ref()
            .map(|finding| finding.fingerprint.clone())
        else {
            return;
        };
        let selected = self
            .findings()
            .iter()
            .find(|finding| finding.fingerprint == selected_fingerprint)
            .cloned();
        self.set_selected_finding(selected);
        self.sync_findings_cursor_to_selected();
    }

    fn log_refresh_findings_error(&mut self, error: anyhow::Error, announce: bool) {
        if announce {
            self.log(
                "error",
                with_next_step(error.to_string(), "full <target> or workspace status"),
            );
        }
    }
}

fn finding_generation_key(finding: &Finding) -> String {
    finding
        .id
        .map(|id| format!("generation:{id}"))
        .unwrap_or_else(|| format!("fingerprint:{}", finding.fingerprint))
}

fn truncate_findings_report(
    mut report: FindingListReport,
    requested_limit: usize,
) -> FindingListReport {
    report.findings.truncate(requested_limit);
    report.aliases.truncate(requested_limit);
    report
}

fn findings_loaded_message(loaded: usize, total: usize) -> String {
    let noun = if total == 1 { "finding" } else { "findings" };
    if loaded == total {
        format!("loaded {total} {noun}")
    } else {
        format!("loaded {loaded} of {total} {noun}")
    }
}

fn review_decisions_for_findings(
    store: &FindingStore,
    findings: &[Finding],
) -> Result<Vec<kuzushi_core::findings::ReviewDecisionRecord>> {
    store.list_review_decisions_for_findings(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::findings::{
        FindingIdentityAuditApprovalRequest, FindingIdentityAuditDisposition,
        FindingIdentityAuditGroupDisposition, IDENTITY_AUDIT_APPROVAL_SCHEMA_VERSION,
    };
    use kuzushi_core::{OptionScope, OptionTarget, Severity, V2Config};

    #[test]
    fn refresh_reads_current_generation_local_decisions_into_queue_and_journey_counts() {
        let target = tempfile::tempdir().unwrap();
        std::fs::write(target.path().join("lib.rs"), "fn candidate() {}\n").unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let mut finding = Finding::new_tool(
            "audit",
            "rule",
            "lib.rs",
            1,
            None,
            Severity::High,
            "older candidate",
        );
        store
            .record_run_started("older", target.path(), "running")
            .unwrap();
        store.insert_finding("older", &finding).unwrap();
        finding.severity = Severity::Medium;
        finding.message = "current candidate".to_string();
        store
            .record_run_started("current", target.path(), "running")
            .unwrap();
        let current_id = store.insert_finding("current", &finding).unwrap();
        store
            .record_auto_triage_locally(
                current_id,
                &kuzushi_core::TriageOutcome {
                    verdict: kuzushi_core::TriageVerdict::FalsePositive,
                    confidence: 0.8,
                    rationale: "No reachable sink".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
        let operator = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.refresh_findings_with_operator_state(false, operator.path());
        assert_eq!(app.findings().len(), 1);
        assert_eq!(app.findings()[0].id, Some(current_id));
        assert_eq!(app.findings()[0].severity, Severity::Medium);
        assert_eq!(app.findings()[0].sources.len(), 2);
        let counts = app.domain().finding_ledger_counts().unwrap();
        assert_eq!(counts.total, 1);
        assert_eq!(counts.reviewed, 1);
        assert_eq!(counts.confirmed, 0);
    }

    #[test]
    fn finding_generation_key_never_collapses_distinct_identity_generations() {
        let mut finding = Finding {
            fingerprint: "legacy-fingerprint".to_string(),
            ..Finding::default()
        };
        assert_eq!(
            finding_generation_key(&finding),
            "fingerprint:legacy-fingerprint"
        );

        finding.identity_id = Some("durable-identity".to_string());
        finding.id = Some(42);
        assert_eq!(finding_generation_key(&finding), "generation:42");
    }

    fn insert_policy_generation(
        store: &FindingStore,
        target: &Path,
        run_id: &str,
        fingerprint: &str,
        dedup_key: &str,
        tool: &str,
    ) {
        store.record_run_started(run_id, target, "running").unwrap();
        let mut finding = Finding::new_tool(
            tool,
            "CWE-78",
            "src/app.rs",
            1,
            Some(1),
            Severity::High,
            "command execution",
        );
        finding.fingerprint = fingerprint.to_string();
        finding.dedup_key = Some(dedup_key.to_string());
        finding.symbol_locator = Some("app::execute".to_string());
        store.insert_finding(run_id, &finding).unwrap();
    }

    fn policy_workspace() -> (tempfile::TempDir, WorkspaceTarget) {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        std::fs::create_dir_all(workspace.root().join("src")).unwrap();
        std::fs::write(workspace.root().join("src/app.rs"), "execute(input);\n").unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        insert_policy_generation(
            &store,
            workspace.root(),
            "strong-a",
            "producer-a",
            "dedup-a",
            "semgrep",
        );
        insert_policy_generation(
            &store,
            workspace.root(),
            "strong-b",
            "producer-b",
            "dedup-b",
            "codeql",
        );
        (temp, workspace)
    }

    fn approve_current_corpus(operator_state: &Path, target: &Path) {
        let evidence =
            kuzushi_core::findings::current_finding_identity_audit_evidence(target).unwrap();
        let dispositions = evidence
            .report
            .suspicious_groups
            .iter()
            .map(|group| FindingIdentityAuditGroupDisposition {
                identity_id: group.identity_id.clone(),
                disposition: FindingIdentityAuditDisposition::Accepted,
                rationale: "reviewed for the TUI policy projection test".to_string(),
            })
            .collect();
        kuzushi_core::findings::approve_finding_identity_audit(
            operator_state,
            target,
            FindingIdentityAuditApprovalRequest {
                schema_version: IDENTITY_AUDIT_APPROVAL_SCHEMA_VERSION,
                canonical_target_key: evidence.canonical_target_key,
                corpus_watermark: evidence.corpus_watermark,
                report_sha256: evidence.report_sha256,
                actor: "test-operator".to_string(),
                dispositions,
            },
        )
        .unwrap();
    }

    fn set_identity_fold_option(app: &mut ShellApp, policy: &str) {
        app.option_store_mut().set_value(
            OptionScope::Session,
            OptionTarget::Tool("sast:scan".to_string()),
            "identityFold",
            serde_json::Value::String(policy.to_string()),
        );
    }

    #[test]
    fn approval_controls_the_default_tui_identity_projection_and_staleness_reverts_it() {
        let (_target_temp, workspace) = policy_workspace();
        let operator = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

        app.refresh_findings_with_operator_state(false, operator.path());
        assert_eq!(app.identity_fold_policy(), IdentityFoldPolicy::Legacy);
        assert_eq!((app.findings().len(), app.findings_total_count()), (2, 2));
        assert_eq!(app.domain().finding_ledger_counts().unwrap().total, 2);

        approve_current_corpus(operator.path(), workspace.root());
        app.refresh_findings_with_operator_state(false, operator.path());
        assert_eq!(app.identity_fold_policy(), IdentityFoldPolicy::Safe);
        assert_eq!((app.findings().len(), app.findings_total_count()), (1, 1));
        assert_eq!(app.finding_aliases(), &["F-0001"]);
        assert_eq!(app.domain().finding_ledger_counts().unwrap().total, 1);

        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        insert_policy_generation(
            &store,
            workspace.root(),
            "strong-c",
            "producer-c",
            "dedup-c",
            "systems-hunt",
        );
        app.refresh_findings_with_operator_state(false, operator.path());
        assert_eq!(app.identity_fold_policy(), IdentityFoldPolicy::Legacy);
        assert_eq!(app.findings().len(), 3);
    }

    #[test]
    fn explicit_safe_option_reprojects_the_refreshed_tui_corpus() {
        let (_target_temp, workspace) = policy_workspace();
        let operator = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.refresh_findings_with_operator_state(false, operator.path());
        assert_eq!(app.findings().len(), 2);

        set_identity_fold_option(&mut app, "safe");
        app.refresh_findings_with_operator_state(false, operator.path());

        assert_eq!(app.identity_fold_policy(), IdentityFoldPolicy::Safe);
        assert_eq!(app.findings().len(), 1);
        assert_eq!(crate::ui_view_models::visible_findings_len(&app), 1);
    }

    #[test]
    fn safe_tui_projection_separates_fallback_signatures_and_attack_chains() {
        let target_temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target_temp.path()).unwrap();
        let operator = tempfile::tempdir().unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        for (run_id, fingerprint, line, signature) in [
            ("fallback-a", "fallback-a", 10, "src/db.rs:10:CWE-89"),
            (
                "fallback-match",
                "fallback-match",
                10,
                "src/db.rs:10:CWE-89",
            ),
            ("fallback-b", "fallback-b", 90, "src/db.rs:90:CWE-89"),
        ] {
            store
                .record_run_started(run_id, workspace.root(), "running")
                .unwrap();
            let mut finding = Finding::new_tool(
                "semgrep",
                "CWE-89",
                "src/db.rs",
                line,
                Some(line),
                Severity::High,
                "SQL injection",
            );
            finding.fingerprint = fingerprint.to_string();
            finding.source_signature = Some(signature.to_string());
            store.insert_finding(run_id, &finding).unwrap();
        }
        insert_policy_generation(
            &store,
            workspace.root(),
            "chain-a",
            "chain-a",
            "chain-dedup-a",
            "chains",
        );
        insert_policy_generation(
            &store,
            workspace.root(),
            "chain-b",
            "chain-b",
            "chain-dedup-b",
            "chains",
        );
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        set_identity_fold_option(&mut app, "safe");

        app.refresh_findings_with_operator_state(false, operator.path());

        let chains = app
            .findings()
            .iter()
            .filter(|finding| finding.tool == "chains")
            .count();
        let fallback_groups = app
            .findings()
            .iter()
            .filter(|finding| finding.tool != "chains")
            .collect::<Vec<_>>();
        assert_eq!(chains, 2);
        assert_eq!(fallback_groups.len(), 2);
        assert_eq!(app.findings().len(), 4);
        let matching_group = fallback_groups
            .into_iter()
            .find(|finding| finding.sources.len() == 2)
            .expect("matching fallback observations fold together");
        for run_id in ["fallback-a", "fallback-match"] {
            assert!(finding_observed_in_runs(
                matching_group,
                &BTreeSet::from([run_id.to_string()]),
            ));
        }
    }

    #[test]
    fn policy_filtered_refresh_keeps_total_alias_and_selection_on_one_projection() {
        let (_target_temp, workspace) = policy_workspace();
        let operator = tempfile::tempdir().unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("low", workspace.root(), "running")
            .unwrap();
        store
            .insert_finding(
                "low",
                &Finding::new_tool(
                    "semgrep",
                    "low-rule",
                    "src/low.rs",
                    1,
                    None,
                    Severity::Low,
                    "low row",
                ),
            )
            .unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        set_identity_fold_option(&mut app, "safe");

        app.refresh_findings_filtered_with_operator_state("rank:low", operator.path());

        assert_eq!((app.findings().len(), app.findings_total_count()), (1, 1));
        assert_eq!(app.finding_aliases(), &["F-0002"]);
        let (alias, selected) = crate::ui_view_models::visible_finding_at_cursor(&app).unwrap();
        assert_eq!(alias, "F-0002");
        assert_eq!(selected.severity, Severity::Low);
    }

    fn filtered_workspace() -> (tempfile::TempDir, WorkspaceTarget) {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("scan-1", workspace.root(), "completed")
            .unwrap();
        for (rule, severity) in [("demo.high", Severity::High), ("demo.low", Severity::Low)] {
            store
                .insert_finding(
                    "scan-1",
                    &Finding::new_semgrep(rule, "src/app.rs", 1, None, severity, rule),
                )
                .unwrap();
        }
        (temp, workspace)
    }

    #[test]
    fn external_refresh_preserves_active_filter_and_projection() {
        let (_temp, workspace) = filtered_workspace();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.refresh_findings_filtered("rank:high");

        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_finding(
                "scan-1",
                &Finding::new_semgrep(
                    "demo.high.second",
                    "src/app.rs",
                    2,
                    None,
                    Severity::High,
                    "second high finding",
                ),
            )
            .unwrap();

        let relative_db = workspace
            .findings_db_path()
            .strip_prefix(workspace.root())
            .unwrap()
            .to_path_buf();
        let effects = app.apply_external_workspace_state_change(&[relative_db]);

        assert!(matches!(
            effects.as_slice(),
            [ShellEffect::RefreshFindings(FindingsRefresh {
                filter: Some(expression),
                ..
            })] if expression == "rank:high"
        ));
        EffectRuntime::execute(&mut app, effects);
        assert_eq!(app.active_findings_filter().as_deref(), Some("rank:high"));
        assert_eq!(app.findings().len(), 2);
        assert_eq!(crate::ui_view_models::visible_findings_len(&app), 2);
    }

    #[test]
    fn unchanged_sqlite_sidecar_event_does_not_reload_findings() {
        let (_temp, workspace) = filtered_workspace();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.refresh_findings(false);

        let effects = app.apply_external_workspace_state_change(&[PathBuf::from(
            ".kuzushi/v3/index.sqlite3-shm",
        )]);

        assert!(effects.is_empty());
    }

    #[test]
    fn findings_command_explicitly_clears_active_filter() {
        let (_temp, workspace) = filtered_workspace();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.refresh_findings_filtered("rank:high");

        let effects = app
            .reduce_command_effects(&ShellCommand::Findings)
            .expect("findings effects");
        EffectRuntime::execute(&mut app, effects);

        assert!(app.active_findings_filter().is_none());
        assert_eq!(app.findings().len(), 2);
        assert_eq!(crate::ui_view_models::visible_findings_len(&app), 2);
    }

    /// The decision-integrity guard: a background reload that inserts rows
    /// ABOVE the cursor must not swap a different finding under it — one-key
    /// backlog decisions target the cursored row, so the cursor follows the
    /// finding's identity across refreshes, not its old index.
    #[test]
    fn refresh_keeps_the_cursor_on_the_same_finding_when_rows_shift() {
        let (_temp, workspace) = filtered_workspace();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.refresh_findings(false);
        assert_eq!(crate::ui_view_models::visible_findings_len(&app), 2);

        // Cursor onto the LAST visible finding (never opened, so
        // selected_finding stays None and cannot mask the regression).
        let last = crate::ui_view_models::visible_findings_len(&app) - 1;
        app.router.findings_mut().set_cursor(last);
        let (_, cursored_before) =
            crate::ui_view_models::visible_finding_at_cursor(&app).expect("cursored row");

        // An external writer lands a CRITICAL finding that sorts above the
        // cursored row in the projection.
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_finding(
                "scan-1",
                &Finding::new_semgrep(
                    "demo.critical.new",
                    "src/app.rs",
                    3,
                    None,
                    Severity::Critical,
                    "externally landed critical",
                ),
            )
            .unwrap();
        app.refresh_findings(false);

        assert_eq!(crate::ui_view_models::visible_findings_len(&app), 3);
        let (_, cursored_after) =
            crate::ui_view_models::visible_finding_at_cursor(&app).expect("cursored row");
        assert_eq!(
            cursored_after.fingerprint, cursored_before.fingerprint,
            "refresh swapped the finding under the cursor"
        );
    }

    /// A reload between the two X presses must disarm the bulk-defer
    /// confirmation — otherwise "press X again to defer 12" could defer a
    /// different (larger) set that landed from an external writer.
    #[test]
    fn refresh_disarms_a_pending_bulk_defer_confirmation() {
        let (_temp, workspace) = filtered_workspace();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.refresh_findings(false);

        app.router.workbench_mut().review_mut().backlog = true;
        app.router.workbench_mut().review_mut().backlog_confirm_bulk = true;

        app.refresh_findings(false);

        assert!(
            !app.router.workbench().review().backlog_confirm_bulk,
            "reload left the bulk-defer confirmation armed"
        );
    }
}

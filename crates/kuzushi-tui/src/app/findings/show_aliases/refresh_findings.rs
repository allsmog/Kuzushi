use super::*;
use std::collections::BTreeMap;

impl ShellApp {
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
        let store = match self.open_store() {
            Ok(store) => store,
            Err(error) => {
                self.log_refresh_findings_error(error, announce);
                return;
            }
        };

        let filter = FindingListFilter::with_limit(FindingListFilter::MAX_LIMIT);
        let read_watermark = self.current_findings_projection_watermark(&store);
        match store.list_findings_filtered(&filter) {
            Ok(report) => self.replace_findings_from_store(
                &store,
                report.findings,
                report.count,
                announce,
                read_watermark,
            ),
            Err(error) => self.log_refresh_findings_error(error.into(), announce),
        }
    }

    pub(crate) fn refresh_findings_filtered(&mut self, expression: &str) {
        let mut filter = match FindingListFilter::from_filter_expression(expression) {
            Ok(filter) => filter,
            Err(error) => {
                self.log("error", format!("invalid findings filter: {error}"));
                return;
            }
        };
        let requested_limit = filter.limit;
        if filter.has_provenance_filter() {
            filter.limit = FindingListFilter::MAX_LIMIT;
        }
        let store = match self.open_store() {
            Ok(store) => store,
            Err(error) => {
                self.log_refresh_findings_error(error, true);
                return;
            }
        };
        self.refresh_journey_ledger_counts(&store);
        let read_watermark = self.current_findings_projection_watermark(&store);
        match store.list_findings_filtered(&filter) {
            Ok(report) => {
                match self.filter_findings_by_provenance(report.findings, report.count, &filter) {
                    Ok((findings, count)) => {
                        let findings = findings.into_iter().take(requested_limit).collect();
                        self.replace_filtered_findings(
                            &store,
                            findings,
                            expression,
                            count,
                            read_watermark,
                        );
                    }
                    Err(error) => self.log("error", format!("invalid findings filter: {error}")),
                }
            }
            Err(error) => self.log_refresh_findings_error(error.into(), true),
        }
    }

    fn filter_findings_by_provenance(
        &self,
        findings: Vec<Finding>,
        count: usize,
        filter: &FindingListFilter,
    ) -> anyhow::Result<(Vec<Finding>, usize)> {
        if !filter.has_provenance_filter() {
            return Ok((findings, count));
        }
        let Some(target) = self.target_path_buf() else {
            anyhow::bail!("revision filters require an active target");
        };
        let runs = kuzushi_core::list_run_summaries(target)?
            .into_iter()
            .map(|summary| (summary.run_id.clone(), summary))
            .collect::<BTreeMap<_, _>>();
        let findings = findings
            .into_iter()
            .filter(|finding| filter.matches_run_provenance(finding, &runs))
            .collect::<Vec<_>>();
        let count = findings.len();
        Ok((findings, count))
    }

    fn replace_findings_from_store(
        &mut self,
        store: &FindingStore,
        findings: Vec<Finding>,
        total_count: usize,
        announce: bool,
        read_watermark: Option<u64>,
    ) {
        let decisions = self.load_review_decisions_for_findings(store, &findings);
        let counts =
            crate::ui_view_models::finding_ledger_counts(&findings, &decisions, total_count);
        self.domain_mut().set_finding_ledger_counts(counts);
        self.replace_findings(findings, decisions, announce, total_count, read_watermark);
    }

    fn refresh_journey_ledger_counts(&mut self, store: &FindingStore) {
        let filter = FindingListFilter::with_limit(FindingListFilter::MAX_LIMIT);
        let Ok(report) = store.list_findings_filtered(&filter) else {
            return;
        };
        let decisions = self.load_review_decisions_for_findings(store, &report.findings);
        let counts = crate::ui_view_models::finding_ledger_counts(
            &report.findings,
            &decisions,
            report.count,
        );
        self.domain_mut().set_finding_ledger_counts(counts);
    }

    fn replace_findings(
        &mut self,
        findings: Vec<Finding>,
        review_decisions: Vec<kuzushi_core::findings::ReviewDecisionRecord>,
        announce: bool,
        total_count: usize,
        read_watermark: Option<u64>,
    ) {
        self.set_findings(findings);
        self.set_findings_total_count(total_count);
        self.set_findings_read_watermark(read_watermark);
        self.set_review_decisions(review_decisions);
        self.set_active_findings_filter(None);
        self.reselect_current_finding();
        self.sync_findings_cursor_to_selected();
        if announce {
            let count = self.findings().len();
            self.log("findings", findings_loaded_message(count, total_count));
        }
    }

    fn replace_filtered_findings(
        &mut self,
        store: &FindingStore,
        findings: Vec<Finding>,
        expression: &str,
        count: usize,
        read_watermark: Option<u64>,
    ) {
        let decisions = self.load_review_decisions_for_findings(store, &findings);
        self.replace_findings(findings, decisions, false, count, read_watermark);
        self.set_active_findings_filter(Some(expression.to_string()));
        self.log(
            "findings",
            format!(
                "filter {expression:?}: loaded {} of {count} matching",
                self.findings().len()
            ),
        );
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
                with_next_step(error.to_string(), "scan <target> or workspace status"),
            );
        }
    }
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
    use kuzushi_core::{Severity, V2Config};

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
}

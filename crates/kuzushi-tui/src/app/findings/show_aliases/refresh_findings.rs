use super::*;
use std::collections::{BTreeMap, BTreeSet};

impl ShellApp {
    pub(crate) fn refresh_findings(&mut self, announce: bool) {
        let store = match self.open_store() {
            Ok(store) => store,
            Err(error) => {
                self.log_refresh_findings_error(error, announce);
                return;
            }
        };

        let filter = FindingListFilter::with_limit(FindingListFilter::MAX_LIMIT);
        match store.list_findings_filtered(&filter) {
            Ok(report) => {
                self.replace_findings_from_store(&store, report.findings, report.count, announce)
            }
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
        match store.list_findings_filtered(&filter) {
            Ok(report) => {
                match self.filter_findings_by_provenance(report.findings, report.count, &filter) {
                    Ok((findings, count)) => {
                        let findings = findings.into_iter().take(requested_limit).collect();
                        self.replace_filtered_findings(&store, findings, expression, count);
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
    ) {
        let decisions = self.load_review_decisions_for_findings(store, &findings);
        self.replace_findings(findings, decisions, announce, total_count);
    }

    fn replace_findings(
        &mut self,
        findings: Vec<Finding>,
        review_decisions: Vec<kuzushi_core::findings::ReviewDecisionRecord>,
        announce: bool,
        total_count: usize,
    ) {
        self.set_findings(findings);
        self.set_findings_total_count(total_count);
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
    ) {
        let decisions = self.load_review_decisions_for_findings(store, &findings);
        self.replace_findings(findings, decisions, false, count);
        self.set_active_findings_filter(Some(expression.to_string()));
        self.log(
            "findings",
            format!(
                "filter {expression:?}: loaded {} of {count} matching",
                self.findings().len()
            ),
        );
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
    let mut seen = BTreeSet::new();
    let mut decisions = Vec::new();
    for finding in findings {
        let Some(finding_id) = finding.id else {
            continue;
        };
        for decision in store.list_review_decisions_for_finding_identity(finding_id)? {
            if seen.insert(decision.id) {
                decisions.push(decision);
            }
        }
    }
    decisions.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(decisions)
}

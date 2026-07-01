use super::*;
use std::collections::BTreeMap;

impl ShellApp {
    pub(crate) fn refresh_findings(&mut self, announce: bool) {
        let store = match self.open_store() {
            Ok(store) => store,
            Err(error) => {
                self.log_refresh_findings_error(error, announce);
                return;
            }
        };

        match store.list_findings(200) {
            Ok(findings) => self.replace_findings(findings, announce),
            Err(error) => self.log_refresh_findings_error(error.into(), announce),
        }
    }

    pub(crate) fn refresh_findings_filtered(&mut self, expression: &str) {
        let parsed = match ParsedFindingsFilter::parse(expression) {
            Ok(parsed) => parsed,
            Err(error) => {
                self.log("error", format!("invalid findings filter: {error}"));
                return;
            }
        };
        let mut filter = match FindingListFilter::from_filter_expression(&parsed.core_expression) {
            Ok(filter) => filter,
            Err(error) => {
                self.log("error", format!("invalid findings filter: {error}"));
                return;
            }
        };
        let requested_limit = filter.limit;
        if parsed.provenance.is_active() {
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
                match self.filter_findings_by_provenance(report.findings, report.count, &parsed) {
                    Ok((findings, count)) => {
                        let findings = findings.into_iter().take(requested_limit).collect();
                        self.replace_filtered_findings(findings, expression, count);
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
        parsed: &ParsedFindingsFilter,
    ) -> anyhow::Result<(Vec<Finding>, usize)> {
        if !parsed.provenance.is_active() {
            return Ok((findings, count));
        }
        let Some(target) = self.target.as_ref() else {
            anyhow::bail!("revision filters require an active target");
        };
        let runs = kuzushi_core::list_run_summaries(target)?
            .into_iter()
            .map(|summary| (summary.run_id.clone(), summary))
            .collect::<BTreeMap<_, _>>();
        let findings = findings
            .into_iter()
            .filter(|finding| parsed.provenance.matches(finding, &runs))
            .collect::<Vec<_>>();
        let count = findings.len();
        Ok((findings, count))
    }

    fn replace_findings(&mut self, findings: Vec<Finding>, announce: bool) {
        self.findings = findings;
        self.reselect_current_finding();
        self.sync_findings_cursor_to_selected();
        if announce {
            let count = self.findings.len();
            self.log(
                "findings",
                format!(
                    "loaded {} {}",
                    count,
                    if count == 1 { "finding" } else { "findings" }
                ),
            );
        }
    }

    fn replace_filtered_findings(
        &mut self,
        findings: Vec<Finding>,
        expression: &str,
        count: usize,
    ) {
        self.findings = findings;
        self.reselect_current_finding();
        self.sync_findings_cursor_to_selected();
        self.log(
            "findings",
            format!(
                "filter {expression:?}: loaded {} of {count} matching",
                self.findings.len()
            ),
        );
    }

    fn reselect_current_finding(&mut self) {
        let Some(selected) = &self.selected_finding else {
            return;
        };
        self.selected_finding = self
            .findings
            .iter()
            .find(|finding| finding.fingerprint == selected.fingerprint)
            .cloned();
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedFindingsFilter {
    core_expression: String,
    provenance: FindingsProvenanceFilter,
}

impl ParsedFindingsFilter {
    fn parse(expression: &str) -> anyhow::Result<Self> {
        let mut core_tokens = Vec::new();
        let mut provenance = FindingsProvenanceFilter::default();
        for token in expression.split_whitespace() {
            if token.starts_with('-') {
                core_tokens.push(token.to_string());
                continue;
            }
            let Some((key, raw_values)) = token.split_once(':') else {
                core_tokens.push(token.to_string());
                continue;
            };
            let values = split_filter_values(raw_values)?;
            match normalize_filter_key(key).as_str() {
                "sha" | "rev" | "revision" => provenance.sha.extend(values),
                "branch" => provenance.branch.extend(values),
                "dirty" => provenance.dirty = Some(parse_dirty_filter(values)?),
                _ => core_tokens.push(token.to_string()),
            }
        }
        Ok(Self {
            core_expression: core_tokens.join(" "),
            provenance,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct FindingsProvenanceFilter {
    sha: Vec<String>,
    branch: Vec<String>,
    dirty: Option<bool>,
}

impl FindingsProvenanceFilter {
    fn is_active(&self) -> bool {
        !self.sha.is_empty() || !self.branch.is_empty() || self.dirty.is_some()
    }

    fn matches(
        &self,
        finding: &Finding,
        runs: &BTreeMap<String, kuzushi_core::RunSummary>,
    ) -> bool {
        let Some(summary) = finding.scan_id.as_ref().and_then(|run_id| runs.get(run_id)) else {
            return false;
        };
        let Some(git) = summary.target_git.as_ref() else {
            return false;
        };
        self.sha_matches(&git.sha)
            && self.branch_matches(git.branch.as_deref())
            && self.dirty_matches(git.dirty)
    }

    fn sha_matches(&self, sha: &str) -> bool {
        self.sha.is_empty()
            || self
                .sha
                .iter()
                .any(|expected| sha.to_ascii_lowercase().starts_with(expected))
    }

    fn branch_matches(&self, branch: Option<&str>) -> bool {
        self.branch.is_empty()
            || branch.is_some_and(|branch| {
                let branch = branch.to_ascii_lowercase();
                self.branch
                    .iter()
                    .any(|expected| branch == *expected || branch.starts_with(expected))
            })
    }

    fn dirty_matches(&self, dirty: bool) -> bool {
        self.dirty.is_none_or(|expected| dirty == expected)
    }
}

fn split_filter_values(raw_values: &str) -> anyhow::Result<Vec<String>> {
    let values = raw_values
        .split(',')
        .map(normalize_filter_value)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if values.is_empty() {
        anyhow::bail!("revision filter requires a value");
    }
    Ok(values)
}

fn normalize_filter_key(key: &str) -> String {
    key.trim().to_ascii_lowercase().replace(['_', '-'], "")
}

fn normalize_filter_value(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn parse_dirty_filter(values: Vec<String>) -> anyhow::Result<bool> {
    let mut parsed = values
        .into_iter()
        .map(|value| match value.as_str() {
            "1" | "true" | "yes" | "dirty" => Ok(true),
            "0" | "false" | "no" | "clean" => Ok(false),
            _ => anyhow::bail!("unknown dirty filter value {value:?}"),
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    parsed.sort();
    parsed.dedup();
    match parsed.as_slice() {
        [value] => Ok(*value),
        _ => anyhow::bail!("dirty filter cannot mix true and false values"),
    }
}

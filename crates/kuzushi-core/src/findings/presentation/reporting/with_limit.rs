use super::*;
use crate::query::{tokenize_filter_expression, FilterToken};
use crate::run_artifacts::RunSummary;
use std::collections::BTreeMap;
mod batch_filter;
mod scope_filter;
use batch_filter::bind_batch_filter;

#[cfg(test)]
mod exact_file_paths_tests;

impl FindingListFilter {
    pub const MAX_LIMIT: usize = 500;

    pub fn with_limit(limit: usize) -> Self {
        Self {
            limit: limit.min(Self::MAX_LIMIT),
            ..Self::default()
        }
    }

    pub fn from_tool_input(input: &Value) -> Result<Self> {
        let mut filter = Self::default();
        filter.apply_filter_input(input)?;
        Ok(filter)
    }

    fn apply_filter_input(&mut self, input: &Value) -> Result<()> {
        self.apply_filter_expression_input(input)?;
        self.scope_id.extend(scope_filter::ids(string_values_any(
            input,
            &["scopeId", "scope_id", "scope"],
        )?)?);
        self.scope_record
            .extend(scope_filter::records(string_values_any(
                input,
                &["scopeRecord", "scope_record"],
            )?)?);
        self.batch_id = bind_batch_filter(
            self.batch_id.take(),
            string_values_any(input, &["batchId", "batch_id", "batch"])?,
        )?;
        self.severity
            .extend(parsed_severities(string_values(input, "severity")?)?);
        self.apply_review_filter_input(input)?;
        self.name =
            merge_optional_field(self.name.take(), normalized_optional_string(input, "name")?);
        self.file_path = merge_optional_field(self.file_path.take(), file_path_input(input)?);
        self.file_paths.extend(literal_file_paths_input(input)?);
        self.run_id.extend(
            string_values_any(input, &["runId", "run_id", "run"])?
                .into_iter()
                .map(normalize_filter_value),
        );
        self.revision_sha
            .extend(normalized_filter_values(string_values_any(
                input,
                &["sha", "rev", "revision"],
            )?));
        self.branch
            .extend(normalized_filter_values(string_values(input, "branch")?));
        self.dirty = merge_dirty_filter(self.dirty, string_values(input, "dirty")?)?;
        self.vuln_source.extend(parsed_sources(string_values_any(
            input,
            &["source", "vulnSource", "vuln_source"],
        )?)?);
        self.limit = parsed_limit(input.get("limit"), self.limit)?;
        Ok(())
    }

    fn apply_review_filter_input(&mut self, input: &Value) -> Result<()> {
        self.verdict.extend(parsed_verdicts(string_values_any(
            input,
            &["verdict", "decision"],
        )?)?);
        self.triage_state
            .extend(parsed_triage_states(string_values(input, "state")?)?);
        self.completeness
            .extend(parsed_completeness_filters(string_values_any(
                input,
                &["completeness", "reviewCompleteness", "review_completeness"],
            )?)?);
        self.triage_band
            .extend(parsed_confidence_bands(string_values(input, "band")?)?);
        self.lifecycle_status
            .extend(parsed_lifecycle_status_filters(string_values_any(
                input,
                &["status", "lifecycleStatus", "lifecycle_status"],
            )?)?);
        self.confidence
            .extend(parsed_confidence_filters(string_values_any(
                input,
                &["confidence", "proofConfidence", "proof_confidence"],
            )?)?);
        Ok(())
    }

    fn apply_filter_expression_input(&mut self, input: &Value) -> Result<()> {
        match input.get("filter") {
            Some(Value::String(expression)) => self.apply_filter_expression(expression),
            Some(_) => anyhow::bail!("findings:list filter must be a string"),
            None => Ok(()),
        }
    }

    pub fn from_parts(
        severity: Vec<String>,
        verdict: Vec<String>,
        name: Option<String>,
        file_path: Option<String>,
        limit: usize,
    ) -> Result<Self> {
        Self::from_parts_full(
            severity,
            verdict,
            name,
            file_path,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            limit,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_parts_full(
        severity: Vec<String>,
        verdict: Vec<String>,
        name: Option<String>,
        file_path: Option<String>,
        vuln_source: Vec<String>,
        completeness: Vec<String>,
        lifecycle_status: Vec<String>,
        confidence: Vec<String>,
        limit: usize,
    ) -> Result<Self> {
        Ok(Self {
            batch_id: None,
            scope_id: Vec::new(),
            scope_record: Vec::new(),
            severity: parsed_part_severities(severity)?,
            verdict: parsed_part_verdicts(verdict)?,
            triage_state: Vec::new(),
            completeness: parsed_part_completeness_filters(completeness)?,
            lifecycle_status: parsed_part_lifecycle_status_filters(lifecycle_status)?,
            confidence: parsed_confidence_filters(confidence)?,
            triage_band: Vec::new(),
            name: normalize_string(name),
            text_terms: Vec::new(),
            file_path: normalize_string(file_path),
            file_paths: Vec::new(),
            run_id: Vec::new(),
            revision_sha: Vec::new(),
            branch: Vec::new(),
            dirty: None,
            vuln_source: parsed_part_sources(vuln_source)?,
            limit: limit.min(Self::MAX_LIMIT),
        })
    }

    /// Adds triage-lifecycle state constraints from raw CLI/tool strings
    /// (e.g. `dismissed`, `fixed`, `open`). Compiles into the same
    /// `triage_state` filter used by the `state:` expression and tool option.
    pub fn with_triage_states(mut self, states: Vec<String>) -> Result<Self> {
        self.triage_state.extend(parsed_triage_states(states)?);
        Ok(self)
    }

    pub fn with_scope_filters(mut self, ids: Vec<String>, records: Vec<String>) -> Result<Self> {
        self.scope_id.extend(scope_filter::ids(ids)?);
        self.scope_record.extend(scope_filter::records(records)?);
        Ok(self)
    }

    pub fn from_filter_expression(expression: &str) -> Result<Self> {
        let mut filter = Self::default();
        filter.apply_filter_expression(expression)?;
        Ok(filter)
    }

    fn apply_filter_expression(&mut self, expression: &str) -> Result<()> {
        for token in tokenize_filter_expression(expression)? {
            self.apply_filter_token(token)?;
        }
        Ok(())
    }

    fn apply_filter_token(&mut self, token: FilterToken) -> Result<()> {
        if token
            .key
            .as_deref()
            .is_some_and(|key| key.eq_ignore_ascii_case("files"))
        {
            self.file_paths.extend(token.values);
            return Ok(());
        }
        match token.key {
            None => {
                self.text_terms.push(normalize_filter_value(token.raw));
                Ok(())
            }
            Some(key) => self.apply_keyed_filter(&key, token.values),
        }
    }

    fn apply_keyed_filter(&mut self, key: &str, values: Vec<String>) -> Result<()> {
        match FilterKey::parse(key)? {
            FilterKey::Rank => self.severity.extend(parsed_severities(values)?),
            FilterKey::Verdict => self.verdict.extend(parsed_verdicts(values)?),
            FilterKey::State => self.triage_state.extend(parsed_triage_states(values)?),
            FilterKey::Completeness => self
                .completeness
                .extend(parsed_completeness_filters(values)?),
            FilterKey::TriageBand => self.triage_band.extend(parsed_confidence_bands(values)?),
            FilterKey::Status => self
                .lifecycle_status
                .extend(parsed_lifecycle_status_filters(values)?),
            FilterKey::Confidence => self.confidence.extend(parsed_confidence_filters(values)?),
            FilterKey::Source => self.vuln_source.extend(parsed_sources(values)?),
            FilterKey::File => {
                self.file_path = merge_optional_contains(self.file_path.take(), values)
            }
            FilterKey::Name => self.name = merge_optional_contains(self.name.take(), values),
            FilterKey::Revision => self.revision_sha.extend(normalized_filter_values(values)),
            FilterKey::Branch => self.branch.extend(normalized_filter_values(values)),
            FilterKey::Dirty => self.dirty = merge_dirty_filter(self.dirty, values)?,
            FilterKey::Run => self
                .run_id
                .extend(values.into_iter().map(normalize_filter_value)),
            FilterKey::Limit => self.limit = parse_limit_token(values)?,
            FilterKey::Batch => self.batch_id = bind_batch_filter(self.batch_id.take(), values)?,
            FilterKey::Scope => self.scope_id.extend(scope_filter::ids(values)?),
            FilterKey::ScopeRecord => self.scope_record.extend(scope_filter::records(values)?),
        }
        Ok(())
    }

    pub fn matches_with_review_decision(
        &self,
        finding: &Finding,
        review_decision: Option<&ReviewDecision>,
    ) -> bool {
        severity_matches(self, finding)
            && triage_state_filter_matches(self, finding)
            && triage_band_matches(self, finding)
            && verdict_matches(self, finding, review_decision)
            && review_completeness_matches(self, finding, review_decision)
            && lifecycle_status_matches(self, finding)
            && confidence_matches(self, finding)
            && name_matches(self, finding)
            && text_terms_match(self, finding)
            && source_matches(self, finding)
            && file_path_matches(self, finding)
            && run_id_matches(self, finding)
    }

    /// True when the filter constrains derived triage-lifecycle states
    /// (`open`/`reviewing`/`confirmed`/`to_fix`/`dismissed`/`fixed`/`removed`).
    pub fn has_derived_triage_state_filter(&self) -> bool {
        self.triage_state.iter().any(|state| state.is_derived())
    }

    /// Derived phase: whether the finding's derived triage state satisfies the
    /// derived filter states. Legacy states are ignored (matched separately).
    pub fn matches_triage_lifecycle(&self, derived: &FindingTriageState) -> bool {
        let derived_filters: Vec<FindingTriageStateFilter> = self
            .triage_state
            .iter()
            .copied()
            .filter(|state| state.is_derived())
            .collect();
        derived_filters.is_empty()
            || derived_filters
                .iter()
                .any(|state| state.matches_derived(derived))
    }

    pub fn has_provenance_filter(&self) -> bool {
        !self.revision_sha.is_empty() || !self.branch.is_empty() || self.dirty.is_some()
    }

    pub fn has_scope_filter(&self) -> bool {
        !self.scope_id.is_empty() || !self.scope_record.is_empty()
    }

    pub fn matches_run_provenance(
        &self,
        finding: &Finding,
        runs: &BTreeMap<String, RunSummary>,
    ) -> bool {
        if !self.has_provenance_filter() {
            return true;
        }
        let Some(summary) = finding.scan_id.as_ref().and_then(|run_id| runs.get(run_id)) else {
            return false;
        };
        self.matches_summary_provenance(summary)
    }

    pub(crate) fn matches_summary_provenance(&self, summary: &RunSummary) -> bool {
        let Some(git) = summary.target_git.as_ref() else {
            return false;
        };
        revision_sha_matches(self, &git.sha)
            && branch_matches(self, git.branch.as_deref())
            && dirty_matches(self, git.dirty)
    }
}

fn parsed_part_severities(values: Vec<String>) -> Result<Vec<Severity>> {
    values
        .into_iter()
        .flat_map(split_csv)
        .map(|value| Severity::try_from(value.as_str()))
        .collect()
}

fn parsed_part_verdicts(values: Vec<String>) -> Result<Vec<FindingVerdictFilter>> {
    values
        .into_iter()
        .flat_map(split_csv)
        .map(|value| FindingVerdictFilter::from_input(&value))
        .collect()
}

fn parsed_part_completeness_filters(
    values: Vec<String>,
) -> Result<Vec<FindingReviewCompletenessFilter>> {
    values
        .into_iter()
        .flat_map(split_csv)
        .map(|value| FindingReviewCompletenessFilter::from_input(&value))
        .collect()
}

fn parsed_part_lifecycle_status_filters(
    values: Vec<String>,
) -> Result<Vec<FindingLifecycleStatusFilter>> {
    values
        .into_iter()
        .flat_map(split_csv)
        .map(|value| FindingLifecycleStatusFilter::from_input(&value))
        .collect()
}

fn parsed_part_sources(values: Vec<String>) -> Result<Vec<VulnSource>> {
    values
        .into_iter()
        .flat_map(split_csv)
        .map(|value| {
            VulnSource::parse(&value)
                .ok_or_else(|| anyhow::anyhow!("unknown vuln source {value:?}"))
        })
        .collect()
}

fn legacy_triage_state_matches(state: FindingTriageStateFilter, finding: &Finding) -> bool {
    match state {
        FindingTriageStateFilter::Untriaged => finding.triage.is_none(),
        FindingTriageStateFilter::Triaged => finding.triage.is_some(),
        FindingTriageStateFilter::NotObserved => finding.observation_gap.is_some(),
        // Derived states (open/reviewing/confirmed/to_fix/dismissed/fixed/removed)
        // are evaluated in the store layer via the lifecycle fold.
        _ => false,
    }
}

fn triage_band_matches(filter: &FindingListFilter, finding: &Finding) -> bool {
    if filter.triage_band.is_empty() {
        return true;
    }
    finding
        .triage
        .as_ref()
        .map(|triage| ConfidenceBand::from_score(triage.confidence))
        .is_some_and(|band| filter.triage_band.contains(&band))
}

fn parsed_confidence_bands(values: Vec<String>) -> Result<Vec<ConfidenceBand>> {
    values
        .into_iter()
        .flat_map(split_csv)
        .map(|value| ConfidenceBand::try_from(value.as_str()))
        .collect()
}

fn severity_matches(filter: &FindingListFilter, finding: &Finding) -> bool {
    filter.severity.is_empty() || filter.severity.contains(&finding.severity)
}

/// Pure phase: only the legacy `untriaged`/`triaged` filter states are
/// evaluated here. Derived states (`open`/`dismissed`/`fixed`/...) are matched
/// against the projected lifecycle in `FindingListFilter::matches_triage_lifecycle`.
fn triage_state_filter_matches(filter: &FindingListFilter, finding: &Finding) -> bool {
    let legacy: Vec<FindingTriageStateFilter> = filter
        .triage_state
        .iter()
        .copied()
        .filter(|state| !state.is_derived())
        .collect();
    legacy.is_empty()
        || legacy
            .iter()
            .any(|state| legacy_triage_state_matches(*state, finding))
}

fn verdict_matches(
    filter: &FindingListFilter,
    finding: &Finding,
    review_decision: Option<&ReviewDecision>,
) -> bool {
    filter.verdict.is_empty()
        || filter
            .verdict
            .contains(&effective_verdict_filter(finding, review_decision))
}

fn effective_verdict_filter(
    finding: &Finding,
    review_decision: Option<&ReviewDecision>,
) -> FindingVerdictFilter {
    review_decision
        .map(|decision| FindingVerdictFilter::from_review_decision(decision.verdict))
        .unwrap_or_else(|| FindingVerdictFilter::from_finding(finding))
}

fn review_completeness_matches(
    filter: &FindingListFilter,
    finding: &Finding,
    review_decision: Option<&ReviewDecision>,
) -> bool {
    filter.completeness.is_empty()
        || filter
            .completeness
            .iter()
            .any(|state| review_completeness_state_matches(*state, finding, review_decision))
}

fn review_completeness_state_matches(
    state: FindingReviewCompletenessFilter,
    finding: &Finding,
    review_decision: Option<&ReviewDecision>,
) -> bool {
    let complete = effective_review_decision(finding, review_decision)
        .is_some_and(|decision| decision.verdict.is_terminal());
    match state {
        FindingReviewCompletenessFilter::Open => !complete,
        FindingReviewCompletenessFilter::Complete => complete,
    }
}

fn effective_review_decision(
    finding: &Finding,
    review_decision: Option<&ReviewDecision>,
) -> Option<ReviewDecision> {
    review_decision.cloned().or_else(|| {
        finding
            .triage
            .as_ref()
            .map(|triage| ReviewDecision::from_triage(triage, finding.triaged_by))
    })
}

fn lifecycle_status_matches(filter: &FindingListFilter, finding: &Finding) -> bool {
    filter.lifecycle_status.is_empty()
        || filter
            .lifecycle_status
            .iter()
            .any(|status| status.as_str() == finding_lifecycle_status(finding))
}

fn confidence_matches(filter: &FindingListFilter, finding: &Finding) -> bool {
    filter.confidence.is_empty()
        || filter
            .confidence
            .contains(&ProofConfidence::classify(finding))
}

fn name_matches(filter: &FindingListFilter, finding: &Finding) -> bool {
    match &filter.name {
        Some(name) => finding
            .title
            .to_ascii_lowercase()
            .contains(&name.to_ascii_lowercase()),
        None => true,
    }
}

fn text_terms_match(filter: &FindingListFilter, finding: &Finding) -> bool {
    filter
        .text_terms
        .iter()
        .all(|term| finding_contains_text(finding, term))
}

fn source_matches(filter: &FindingListFilter, finding: &Finding) -> bool {
    if filter.vuln_source.is_empty() {
        return true;
    }
    let observed = finding
        .vuln_source
        .unwrap_or_else(|| VulnSource::from_tool(&finding.tool));
    filter.vuln_source.contains(&observed)
}

fn file_path_matches(filter: &FindingListFilter, finding: &Finding) -> bool {
    let substring_matches = match &filter.file_path {
        Some(file_path) => finding
            .file_path
            .to_ascii_lowercase()
            .contains(&file_path.to_ascii_lowercase()),
        None => true,
    };
    substring_matches && exact_file_paths_match(&filter.file_paths, &finding.file_path)
}

fn exact_file_paths_match(paths: &[String], file: &str) -> bool {
    if paths.is_empty() {
        return true;
    }
    let file = normalized_exact_path(file);
    paths.iter().any(|path| normalized_exact_path(path) == file)
}

fn normalized_exact_path(path: &str) -> String {
    #[cfg(windows)]
    let path = path.replace('\\', "/");
    path.trim_start_matches("./").to_string()
}

fn run_id_matches(filter: &FindingListFilter, finding: &Finding) -> bool {
    filter.run_id.is_empty()
        || filter
            .run_id
            .iter()
            .any(|run_id| run_matches(finding, run_id))
}

fn revision_sha_matches(filter: &FindingListFilter, sha: &str) -> bool {
    filter.revision_sha.is_empty()
        || filter
            .revision_sha
            .iter()
            .any(|expected| sha.to_ascii_lowercase().starts_with(expected))
}

fn branch_matches(filter: &FindingListFilter, branch: Option<&str>) -> bool {
    filter.branch.is_empty()
        || branch.is_some_and(|branch| {
            let branch = branch.to_ascii_lowercase();
            filter
                .branch
                .iter()
                .any(|expected| branch == *expected || branch.starts_with(expected))
        })
}

fn dirty_matches(filter: &FindingListFilter, dirty: bool) -> bool {
    filter.dirty.is_none_or(|expected| dirty == expected)
}

fn finding_contains_text(finding: &Finding, term: &str) -> bool {
    let term = term.to_ascii_lowercase();
    [
        finding.title.as_str(),
        finding.file_path.as_str(),
        finding.rule_id.as_str(),
        finding.message.as_str(),
    ]
    .into_iter()
    .any(|value| value.to_ascii_lowercase().contains(&term))
}

fn run_matches(finding: &Finding, run_id: &str) -> bool {
    finding
        .scan_id
        .as_deref()
        .map(|scan_id| {
            let scan_id = scan_id.to_ascii_lowercase();
            scan_id == run_id || scan_id.starts_with(run_id)
        })
        .unwrap_or(false)
}

fn normalize_filter_key(key: &str) -> String {
    key.trim()
        .trim_start_matches('-')
        .to_ascii_lowercase()
        .replace(['_', '-'], "")
}

fn string_values_any(input: &Value, keys: &[&str]) -> Result<Vec<String>> {
    let mut values = Vec::new();
    for key in keys {
        values.extend(string_values(input, key)?);
    }
    Ok(values)
}

fn file_path_input(input: &Value) -> Result<Option<String>> {
    Ok(normalized_optional_string(input, "filePath")?
        .or(normalized_optional_string(input, "file_path")?))
}

fn literal_file_paths_input(input: &Value) -> Result<Vec<String>> {
    let Some(value) = input.get("filePaths").or_else(|| input.get("file_paths")) else {
        return Ok(Vec::new());
    };
    serde_json::from_value(value.clone())
        .context("filePaths must be an array of literal file path strings")
}

fn parsed_severities(values: Vec<String>) -> Result<Vec<Severity>> {
    values
        .into_iter()
        .map(|value| Severity::try_from(value.as_str()))
        .collect()
}

fn parsed_verdicts(values: Vec<String>) -> Result<Vec<FindingVerdictFilter>> {
    values
        .into_iter()
        .map(|value| FindingVerdictFilter::from_input(&value))
        .collect()
}

fn parsed_triage_states(values: Vec<String>) -> Result<Vec<FindingTriageStateFilter>> {
    values
        .into_iter()
        .map(|value| FindingTriageStateFilter::from_input(&value))
        .collect()
}

fn parsed_completeness_filters(
    values: Vec<String>,
) -> Result<Vec<FindingReviewCompletenessFilter>> {
    values
        .into_iter()
        .map(|value| FindingReviewCompletenessFilter::from_input(&value))
        .collect()
}

fn parsed_lifecycle_status_filters(
    values: Vec<String>,
) -> Result<Vec<FindingLifecycleStatusFilter>> {
    values
        .into_iter()
        .map(|value| FindingLifecycleStatusFilter::from_input(&value))
        .collect()
}

fn parsed_confidence_filters(values: Vec<String>) -> Result<Vec<ProofConfidence>> {
    values
        .into_iter()
        .flat_map(split_csv)
        .map(|value| ProofConfidence::try_from(value.as_str()))
        .collect()
}

fn parsed_sources(values: Vec<String>) -> Result<Vec<VulnSource>> {
    values
        .into_iter()
        .map(|value| {
            VulnSource::parse(&value)
                .ok_or_else(|| anyhow::anyhow!("unknown vuln source {value:?}"))
        })
        .collect()
}

enum FilterKey {
    Batch,
    Scope,
    ScopeRecord,
    Rank,
    Verdict,
    State,
    Completeness,
    TriageBand,
    Status,
    Confidence,
    Source,
    File,
    Name,
    Revision,
    Branch,
    Dirty,
    Run,
    Limit,
}

impl FilterKey {
    fn parse(key: &str) -> Result<Self> {
        match normalize_filter_key(key).as_str() {
            "batch" | "batchid" => Ok(Self::Batch),
            "scope" | "scopeid" => Ok(Self::Scope),
            "scoperecord" => Ok(Self::ScopeRecord),
            "rank" | "severity" => Ok(Self::Rank),
            "verdict" | "decision" | "conf" | "confirmation" => Ok(Self::Verdict),
            "state" | "triage" => Ok(Self::State),
            "completeness" | "review" | "reviewstate" => Ok(Self::Completeness),
            "band" => Ok(Self::TriageBand),
            "status" | "lifecycle" | "lifecyclestatus" => Ok(Self::Status),
            "confidence" | "proof" | "proofstate" | "proofconfidence" => Ok(Self::Confidence),
            "source" | "channel" => Ok(Self::Source),
            "file" | "path" => Ok(Self::File),
            "name" | "title" | "q" => Ok(Self::Name),
            "rev" | "revision" | "sha" => Ok(Self::Revision),
            "branch" => Ok(Self::Branch),
            "dirty" => Ok(Self::Dirty),
            "run" | "runid" | "scan" => Ok(Self::Run),
            "limit" => Ok(Self::Limit),
            "owner" | "changed" | "strategy" | "strat" => unsupported_future_key(key),
            other => anyhow::bail!("unknown findings:list filter key {other:?}"),
        }
    }
}

fn unsupported_future_key<T>(key: &str) -> Result<T> {
    anyhow::bail!(
        "findings:list filter key {key:?} is not supported until provenance indexing is available"
    )
}

fn normalize_filter_value(value: String) -> String {
    value.trim().to_ascii_lowercase()
}

fn normalized_filter_values(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(normalize_filter_value)
        .filter(|value| !value.is_empty())
        .collect()
}

fn merge_dirty_filter(current: Option<bool>, values: Vec<String>) -> Result<Option<bool>> {
    let Some(next) = parse_dirty_filter(values)? else {
        return Ok(current);
    };
    match current {
        Some(current) if current != next => {
            anyhow::bail!("dirty filter cannot mix true and false values")
        }
        _ => Ok(Some(next)),
    }
}

fn parse_dirty_filter(values: Vec<String>) -> Result<Option<bool>> {
    let mut parsed = normalized_filter_values(values)
        .into_iter()
        .map(|value| match value.as_str() {
            "1" | "true" | "yes" | "dirty" => Ok(true),
            "0" | "false" | "no" | "clean" => Ok(false),
            _ => anyhow::bail!("unknown dirty filter value {value:?}"),
        })
        .collect::<Result<Vec<_>>>()?;
    parsed.sort();
    parsed.dedup();
    match parsed.as_slice() {
        [] => Ok(None),
        [value] => Ok(Some(*value)),
        _ => anyhow::bail!("dirty filter cannot mix true and false values"),
    }
}

fn merge_optional_contains(current: Option<String>, values: Vec<String>) -> Option<String> {
    let next = values
        .into_iter()
        .map(normalize_filter_value)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    match (current, next.is_empty()) {
        (Some(current), false) => Some(format!("{current} {next}")),
        (Some(current), true) => Some(current),
        (None, false) => Some(next),
        (None, true) => None,
    }
}

fn merge_optional_field(current: Option<String>, next: Option<String>) -> Option<String> {
    match (current, next) {
        (Some(current), Some(next)) => Some(format!("{current} {next}")),
        (Some(current), None) => Some(current),
        (None, Some(next)) => Some(next),
        (None, None) => None,
    }
}

fn parse_limit_token(values: Vec<String>) -> Result<usize> {
    if values.len() != 1 {
        anyhow::bail!("findings:list filter limit expects one value");
    }
    values[0]
        .parse::<usize>()
        .with_context(|| "findings:list filter limit must be a non-negative integer")
        .map(|value| value.min(FindingListFilter::MAX_LIMIT))
}

fn parsed_limit(value: Option<&Value>, current: usize) -> Result<usize> {
    match value {
        Some(value) => parse_limit_value(value),
        None => Ok(current),
    }
}

fn parse_limit_value(value: &Value) -> Result<usize> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .with_context(|| "findings:list limit must be a non-negative integer")
            .map(|value| value.min(FindingListFilter::MAX_LIMIT as u64) as usize),
        Value::String(value) => value
            .parse::<usize>()
            .with_context(|| "findings:list limit must be a non-negative integer")
            .map(|value| value.min(FindingListFilter::MAX_LIMIT)),
        _ => anyhow::bail!("findings:list limit must be a number"),
    }
}

#[cfg(test)]
mod triage_band_and_state_tests {
    use super::*;

    fn triaged(verdict: TriageVerdict, confidence: f32) -> Finding {
        let mut finding = Finding::new_semgrep(
            "demo.rule",
            "src/a.rs",
            1,
            Some(1),
            Severity::High,
            "demo finding",
        );
        finding.triage = Some(TriageOutcome {
            first_link: None,
            refute_reason: None,
            verdict,
            confidence,
            rationale: "test".to_string(),
            cost_usd: 0.0,
            cost_usd_exact: true,
            estimated_cost_usd: None,
        });
        finding
    }

    fn untriaged() -> Finding {
        Finding::new_semgrep(
            "demo.rule",
            "src/a.rs",
            1,
            Some(1),
            Severity::High,
            "demo finding",
        )
    }

    fn matches(filter: &FindingListFilter, finding: &Finding) -> bool {
        filter.matches_with_review_decision(finding, None)
    }

    #[test]
    fn band_high_matches_banded_triage_and_excludes_untriaged() {
        let filter = FindingListFilter::from_filter_expression("band:high").unwrap();
        assert_eq!(filter.triage_band, vec![ConfidenceBand::High]);
        assert!(matches(&filter, &triaged(TriageVerdict::TruePositive, 0.9)));
        assert!(!matches(
            &filter,
            &triaged(TriageVerdict::TruePositive, 0.5)
        ));
        assert!(!matches(&filter, &untriaged()));
    }

    #[test]
    fn band_key_and_unknown_value_error() {
        assert_eq!(
            FindingListFilter::from_filter_expression("band:low")
                .unwrap()
                .triage_band,
            vec![ConfidenceBand::Low]
        );
        assert!(FindingListFilter::from_filter_expression("band:bogus").is_err());
    }

    #[test]
    fn conf_key_still_means_verdict_not_triage_band() {
        // `conf` remains a verdict alias; it must not populate the band filter.
        let filter = FindingListFilter::from_filter_expression("conf:confirmed").unwrap();
        assert!(filter.triage_band.is_empty());
        assert!(filter.confidence.is_empty());
        assert_eq!(filter.verdict, vec![FindingVerdictFilter::TruePositive]);
    }
}

#[cfg(test)]
mod confidence_filter_tests {
    use super::*;
    use crate::findings::domain::StaticProofState;

    fn finding_with_state(fingerprint: &str, state: Option<StaticProofState>) -> Finding {
        Finding {
            fingerprint: fingerprint.to_string(),
            static_proof_state: state,
            ..Finding::default()
        }
    }

    #[test]
    fn confidence_key_parses_to_the_confidence_axis() {
        let filter = FindingListFilter::from_filter_expression("confidence:likely").unwrap();
        assert_eq!(filter.confidence, vec![ProofConfidence::Likely]);
        // The `proof:` alias also targets confidence.
        let by_proof = FindingListFilter::from_filter_expression("proof:confirmed").unwrap();
        assert_eq!(by_proof.confidence, vec![ProofConfidence::Confirmed]);
    }

    #[test]
    fn conf_key_still_maps_to_verdict_not_confidence() {
        // Regression: `conf` is a pre-existing verdict alias; it must not be
        // silently reassigned to the confidence axis.
        let filter = FindingListFilter::from_filter_expression("conf:tp").unwrap();
        assert!(filter.confidence.is_empty());
        assert_eq!(filter.verdict, vec![FindingVerdictFilter::TruePositive]);
    }

    #[test]
    fn confidence_matcher_filters_by_band() {
        let filter = FindingListFilter::from_filter_expression("confidence:likely").unwrap();
        let likely = finding_with_state("a", Some(StaticProofState::SourceSinkLinked));
        let unverified = finding_with_state("b", Some(StaticProofState::SignalOnly));
        assert!(filter.matches_with_review_decision(&likely, None));
        assert!(!filter.matches_with_review_decision(&unverified, None));
    }

    #[test]
    fn empty_confidence_filter_admits_everything() {
        let filter = FindingListFilter::default();
        let unverified = finding_with_state("b", Some(StaticProofState::SignalOnly));
        assert!(filter.matches_with_review_decision(&unverified, None));
    }
}

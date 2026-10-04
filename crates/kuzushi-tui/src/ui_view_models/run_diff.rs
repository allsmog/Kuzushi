use super::review_state::EffectiveReviewStateIndex;
use crate::app::{JsonFileState, ViewDataState};
use crate::ShellApp;
use kuzushi_core::findings::{ReviewDecisionVerdict, TriageVerdict};
use kuzushi_core::{RunId, RunTargetGitMetadata};
use std::collections::{BTreeMap, BTreeSet};

const FINDINGS_FILE: &str = "findings.json";
const RUN_FILE: &str = "run.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunDiffModel {
    pub(crate) left_run: String,
    pub(crate) right_run: String,
    pub(crate) left_revision: String,
    pub(crate) right_revision: String,
    pub(crate) left_source: String,
    pub(crate) right_source: String,
    pub(crate) left_context: String,
    pub(crate) right_context: String,
    pub(crate) context_status: String,
    pub(crate) left_status: String,
    pub(crate) right_status: String,
    pub(crate) new_findings: Vec<RunDiffFindingRow>,
    pub(crate) not_seen: Vec<RunDiffFindingRow>,
    pub(crate) changed_findings: Vec<RunDiffChangedRow>,
    pub(crate) uncertain_matches: Vec<RunDiffUncertainMatchRow>,
    pub(crate) unchanged_findings: Vec<RunDiffFindingRow>,
    pub(crate) decision_summary: Option<RunDiffDecisionSummary>,
    pub(crate) warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunDiffFindingRow {
    pub(crate) key: String,
    pub(crate) title: String,
    pub(crate) state: RunDiffFindingState,
    pub(crate) location: String,
    pub(crate) file_path: String,
    pub(crate) reassessment_block: Option<String>,
    pub(crate) tool: String,
    pub(crate) match_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunDiffFindingState {
    pub(crate) severity: String,
    pub(crate) confidence: String,
    pub(crate) verdict: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunDiffChangedRow {
    pub(crate) key: String,
    pub(crate) title: String,
    pub(crate) before: RunDiffFindingState,
    pub(crate) after: RunDiffFindingState,
    pub(crate) location: String,
    pub(crate) tool: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunDiffUncertainMatchRow {
    pub(crate) left_key: String,
    pub(crate) right_key: String,
    pub(crate) title: String,
    pub(crate) before: RunDiffFindingState,
    pub(crate) after: RunDiffFindingState,
    pub(crate) left_location: String,
    pub(crate) right_location: String,
    pub(crate) tool: String,
    pub(crate) reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RunDiffDecisionSummary {
    pub(crate) identities: usize,
    pub(crate) with_stored_decision: usize,
    pub(crate) carry_forward: usize,
    pub(crate) conflicts: usize,
}

pub(crate) fn run_diff_model(app: &ShellApp, left: &str, right: &str) -> RunDiffModel {
    let mut warnings = Vec::new();
    append_run_id_warning(&mut warnings, "left", left);
    append_run_id_warning(&mut warnings, "right", right);
    let left_metadata = run_metadata(app, left);
    let right_metadata = run_metadata(app, right);
    append_status_warning(&mut warnings, left, &left_metadata.status);
    append_status_warning(&mut warnings, right, &right_metadata.status);
    let left_findings = load_run_findings(app, left, &mut warnings);
    let right_findings = load_run_findings(app, right, &mut warnings);
    let mut rows = classified_run_diff_rows(&left_findings, &right_findings);
    assessment::classify_absences(
        app,
        right,
        &left_metadata,
        &right_metadata,
        &mut rows.not_seen,
    );
    let decision_summary = run_diff_decision_summary(app, &right_findings);

    RunDiffModel {
        left_run: left.to_string(),
        right_run: right.to_string(),
        left_revision: left_metadata.revision,
        right_revision: right_metadata.revision,
        left_source: assessment::source_label(app, left),
        right_source: assessment::source_label(app, right),
        left_context: assessment::context_label(app, left),
        right_context: assessment::context_label(app, right),
        context_status: assessment::context_comparison(app, left, right),
        left_status: left_metadata.status,
        right_status: right_metadata.status,
        new_findings: rows.new_findings,
        not_seen: rows.not_seen,
        changed_findings: rows.changed_findings,
        uncertain_matches: rows.uncertain_matches,
        unchanged_findings: rows.unchanged_findings,
        decision_summary,
        warnings,
    }
}

struct ClassifiedRunDiffRows {
    new_findings: Vec<RunDiffFindingRow>,
    not_seen: Vec<RunDiffFindingRow>,
    changed_findings: Vec<RunDiffChangedRow>,
    uncertain_matches: Vec<RunDiffUncertainMatchRow>,
    unchanged_findings: Vec<RunDiffFindingRow>,
}

fn classified_run_diff_rows(
    left_findings: &BTreeMap<String, RunDiffFindingRow>,
    right_findings: &BTreeMap<String, RunDiffFindingRow>,
) -> ClassifiedRunDiffRows {
    let uncertain_matches = uncertain_finding_matches(left_findings, right_findings);
    let uncertain_left_keys = uncertain_left_keys(&uncertain_matches);
    let uncertain_right_keys = uncertain_right_keys(&uncertain_matches);
    ClassifiedRunDiffRows {
        new_findings: unmatched_rows(right_findings, left_findings, &uncertain_right_keys),
        not_seen: unmatched_rows(left_findings, right_findings, &uncertain_left_keys),
        changed_findings: changed_findings(left_findings, right_findings),
        uncertain_matches,
        unchanged_findings: unchanged_findings(left_findings, right_findings),
    }
}

fn unmatched_rows(
    source: &BTreeMap<String, RunDiffFindingRow>,
    other: &BTreeMap<String, RunDiffFindingRow>,
    excluded: &BTreeSet<String>,
) -> Vec<RunDiffFindingRow> {
    source
        .iter()
        .filter(|(key, _)| !other.contains_key(*key) && !excluded.contains(*key))
        .map(|(_, row)| row.clone())
        .collect()
}

fn uncertain_left_keys(matches: &[RunDiffUncertainMatchRow]) -> BTreeSet<String> {
    matches.iter().map(|row| row.left_key.clone()).collect()
}

fn uncertain_right_keys(matches: &[RunDiffUncertainMatchRow]) -> BTreeSet<String> {
    matches.iter().map(|row| row.right_key.clone()).collect()
}

fn run_diff_decision_summary(
    app: &ShellApp,
    right_findings: &BTreeMap<String, RunDiffFindingRow>,
) -> Option<RunDiffDecisionSummary> {
    if app.findings().is_empty() {
        return None;
    }
    let review_index = EffectiveReviewStateIndex::from_findings_and_decisions(
        app.findings(),
        app.review_decisions(),
    );
    let mut summary = RunDiffDecisionSummary::default();
    for (identity_id, row) in right_findings
        .iter()
        .filter(|(key, _)| is_identity_key(key))
    {
        summary.identities += 1;
        let Some(stored) = review_index.verdict_for_identity(identity_id) else {
            continue;
        };
        summary.add_stored_decision(stored, &row.state);
    }
    Some(summary)
}

fn is_identity_key(key: &str) -> bool {
    key.starts_with("fi_")
}

impl RunDiffDecisionSummary {
    fn add_stored_decision(&mut self, stored: ReviewDecisionVerdict, state: &RunDiffFindingState) {
        self.with_stored_decision += 1;
        match snapshot_review_verdict(state) {
            Some(snapshot) if snapshot != stored => self.conflicts += 1,
            Some(_) => {}
            None => self.carry_forward += 1,
        }
    }
}

fn snapshot_review_verdict(state: &RunDiffFindingState) -> Option<ReviewDecisionVerdict> {
    let verdict = (state.verdict != "-").then_some(state.verdict.as_str())?;
    ReviewDecisionVerdict::from_str(verdict).or_else(|| {
        TriageVerdict::try_from(verdict)
            .ok()
            .map(ReviewDecisionVerdict::from_triage_verdict)
    })
}

fn changed_findings(
    left: &BTreeMap<String, RunDiffFindingRow>,
    right: &BTreeMap<String, RunDiffFindingRow>,
) -> Vec<RunDiffChangedRow> {
    left.iter()
        .filter_map(|(key, before)| changed_finding_row(key, before, right))
        .collect()
}

fn changed_finding_row(
    key: &str,
    before: &RunDiffFindingRow,
    right: &BTreeMap<String, RunDiffFindingRow>,
) -> Option<RunDiffChangedRow> {
    let after = right.get(key)?;
    (before.state != after.state).then(|| RunDiffChangedRow {
        key: key.to_string(),
        title: after.title.clone(),
        before: before.state.clone(),
        after: after.state.clone(),
        location: after.location.clone(),
        tool: after.tool.clone(),
    })
}

fn unchanged_findings(
    left: &BTreeMap<String, RunDiffFindingRow>,
    right: &BTreeMap<String, RunDiffFindingRow>,
) -> Vec<RunDiffFindingRow> {
    right
        .iter()
        .filter(|(key, after)| {
            left.get(*key)
                .is_some_and(|before| before.state == after.state)
        })
        .map(|(_, row)| row.clone())
        .collect()
}

fn uncertain_finding_matches(
    left: &BTreeMap<String, RunDiffFindingRow>,
    right: &BTreeMap<String, RunDiffFindingRow>,
) -> Vec<RunDiffUncertainMatchRow> {
    let left_candidates = unmatched_by_match_key(left, right);
    let right_candidates = unmatched_by_match_key(right, left);
    left_candidates
        .iter()
        .filter_map(|(match_key, left_rows)| {
            uncertain_match_row(left_rows, right_candidates.get(match_key)?)
        })
        .collect()
}

fn unmatched_by_match_key(
    source: &BTreeMap<String, RunDiffFindingRow>,
    other: &BTreeMap<String, RunDiffFindingRow>,
) -> BTreeMap<String, Vec<RunDiffFindingRow>> {
    let mut grouped = BTreeMap::<String, Vec<RunDiffFindingRow>>::new();
    for (key, row) in source.iter().filter(|(key, _)| !other.contains_key(*key)) {
        let Some(match_key) = row.match_key.as_ref() else {
            continue;
        };
        grouped
            .entry(match_key.clone())
            .or_default()
            .push(row.with_key(key));
    }
    grouped
}

fn uncertain_match_row(
    left_rows: &[RunDiffFindingRow],
    right_rows: &[RunDiffFindingRow],
) -> Option<RunDiffUncertainMatchRow> {
    let ([left], [right]) = (left_rows, right_rows) else {
        return None;
    };
    Some(RunDiffUncertainMatchRow {
        left_key: left.key.clone(),
        right_key: right.key.clone(),
        title: right.title.clone(),
        before: left.state.clone(),
        after: right.state.clone(),
        left_location: left.location.clone(),
        right_location: right.location.clone(),
        tool: right.tool.clone(),
        reason: "same tool/rule/file/title but different identity or fingerprint; review before carrying decisions".to_string(),
    })
}

impl RunDiffFindingRow {
    fn with_key(&self, key: &str) -> Self {
        Self {
            key: key.to_string(),
            ..self.clone()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunDiffMetadata {
    target: Option<String>,
    revision: String,
    status: String,
}

fn run_metadata(app: &ShellApp, run_id: &str) -> RunDiffMetadata {
    let run_state = run_json_state(app, run_id, RUN_FILE);
    match run_state {
        ViewDataState::Ready(run_state) => RunDiffMetadata {
            target: assessment::run_target(&run_state),
            revision: run_revision_label(run_state.clone()),
            status: run_status_label(run_state),
        },
        ViewDataState::NotRequested | ViewDataState::Loading => RunDiffMetadata {
            target: None,
            revision: "rev:loading".to_string(),
            status: "loading".to_string(),
        },
    }
}

/// Name the side — two bad run ids would otherwise emit indistinguishable
/// duplicate warnings. The raw value is deliberately never reflected
/// (traversal/control characters must not reach the screen).
fn append_run_id_warning(warnings: &mut Vec<String>, side: &str, run_id: &str) {
    if let Err(error) = RunId::parse(run_id) {
        warnings.push(format!("invalid run id ({side}): {error}"));
    }
}

fn append_status_warning(warnings: &mut Vec<String>, run_id: &str, status: &str) {
    if matches!(status, "completed" | "unknown" | "loading") {
        return;
    }
    warnings.push(format!(
        "{run_id}: run status {status}; not_seen entries may reflect incomplete coverage"
    ));
}

fn load_run_findings(
    app: &ShellApp,
    run_id: &str,
    warnings: &mut Vec<String>,
) -> BTreeMap<String, RunDiffFindingRow> {
    if RunId::parse(run_id).is_err() {
        return BTreeMap::new();
    }
    let value = match run_json_state(app, run_id, FINDINGS_FILE) {
        ViewDataState::Ready(JsonFileState::Present(value)) => value,
        ViewDataState::Ready(JsonFileState::Missing) => {
            warnings.push(format!("{run_id}: missing {FINDINGS_FILE}"));
            return BTreeMap::new();
        }
        ViewDataState::Ready(
            JsonFileState::NonFile | JsonFileState::Malformed | JsonFileState::Unreadable,
        ) => {
            warnings.push(format!("{run_id}: malformed {FINDINGS_FILE}"));
            return BTreeMap::new();
        }
        ViewDataState::NotRequested | ViewDataState::Loading => {
            warnings.push(format!("{run_id}: loading {FINDINGS_FILE}"));
            return BTreeMap::new();
        }
    };
    let Some(findings) = findings_array(&value) else {
        warnings.push(format!("{run_id}: {FINDINGS_FILE} has no findings array"));
        return BTreeMap::new();
    };
    findings
        .iter()
        .filter_map(run_diff_finding_row)
        .map(|row| (row.key.clone(), row))
        .collect()
}

fn run_json_state(app: &ShellApp, run_id: &str, leaf: &str) -> ViewDataState<JsonFileState> {
    let Some(target) = app.target() else {
        return ViewDataState::Ready(JsonFileState::Missing);
    };
    app.workbench_cache()
        .borrow()
        .cached_run_artifact_json(target, run_id, leaf)
}

fn findings_array(value: &serde_json::Value) -> Option<&Vec<serde_json::Value>> {
    value.as_array().or_else(|| {
        value
            .get("findings")
            .or_else(|| value.pointer("/data/findings"))
            .and_then(serde_json::Value::as_array)
    })
}

fn run_diff_finding_row(value: &serde_json::Value) -> Option<RunDiffFindingRow> {
    let key = finding_key(value)?;
    let file = string_field(value, &["filePath", "file_path", "path"]).unwrap_or("-");
    let line = integer_field(value, &["startLine", "start_line", "line"]);
    Some(RunDiffFindingRow {
        key,
        title: finding_title(value),
        state: run_diff_finding_state(value),
        location: location_label(file, line),
        file_path: file.to_string(),
        reassessment_block: None,
        tool: string_field(value, &["tool", "source"])
            .unwrap_or("-")
            .to_string(),
        match_key: finding_uncertain_match_key(value),
    })
}

fn run_diff_finding_state(value: &serde_json::Value) -> RunDiffFindingState {
    RunDiffFindingState {
        severity: string_field(value, &["severity", "rank"])
            .unwrap_or("unknown")
            .to_string(),
        confidence: nested_scalar_field(value, "triage", &["confidence"]),
        verdict: nested_string_field(value, "triage", &["verdict"]),
    }
}

fn finding_key(value: &serde_json::Value) -> Option<String> {
    string_field(
        value,
        &[
            "identityId",
            "identity_id",
            "fingerprint",
            "id",
            "dedupKey",
            "dedup_key",
        ],
    )
    .map(ToString::to_string)
    .or_else(|| {
        let rule = string_field(value, &["ruleId", "rule_id", "rule"]).unwrap_or("-");
        let file = string_field(value, &["filePath", "file_path", "path"]).unwrap_or("-");
        let line = integer_field(value, &["startLine", "start_line", "line"]).unwrap_or(0);
        (rule != "-" || file != "-").then(|| format!("{rule}:{file}:{line}"))
    })
}

fn finding_title(value: &serde_json::Value) -> String {
    string_field(value, &["title", "message", "summary"])
        .map(ToString::to_string)
        .or_else(|| {
            value
                .pointer("/message/text")
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string)
        })
        .or_else(|| string_field(value, &["ruleId", "rule_id"]).map(ToString::to_string))
        .unwrap_or_else(|| "untitled finding".to_string())
}

fn finding_uncertain_match_key(value: &serde_json::Value) -> Option<String> {
    let tool = normalized_optional_field(value, &["tool", "source"]);
    let rule = normalized_optional_field(value, &["ruleId", "rule_id", "rule"])?;
    let file = normalized_path_field(value, &["filePath", "file_path", "path"])?;
    let title = normalize_match_token(&finding_title(value));
    (!title.is_empty()).then(|| {
        format!(
            "{}\u{1f}{rule}\u{1f}{file}\u{1f}{title}",
            tool.unwrap_or_else(|| "-".to_string())
        )
    })
}

fn normalized_optional_field(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    string_field(value, keys)
        .map(normalize_match_token)
        .filter(|value| !value.is_empty())
}

fn normalized_path_field(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    string_field(value, keys)
        .map(|value| normalize_match_token(&value.replace('\\', "/")))
        .filter(|value| !value.is_empty())
}

fn normalize_match_token(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn string_field<'a>(value: &'a serde_json::Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(serde_json::Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn nested_string_field(value: &serde_json::Value, child: &str, keys: &[&str]) -> String {
    string_field(value, keys)
        .or_else(|| {
            value
                .get(child)
                .and_then(|nested| string_field(nested, keys))
        })
        .unwrap_or("-")
        .to_string()
}

fn nested_scalar_field(value: &serde_json::Value, child: &str, keys: &[&str]) -> String {
    scalar_field(value, keys)
        .or_else(|| {
            value
                .get(child)
                .and_then(|nested| scalar_field(nested, keys))
        })
        .unwrap_or_else(|| "-".to_string())
}

fn scalar_field(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .filter_map(|key| value.get(*key))
        .filter(|field| field.is_string() || field.is_number() || field.is_boolean())
        .map(scalar_string)
        .next()
}

fn scalar_string(field: &serde_json::Value) -> String {
    field
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| field.to_string())
}

fn integer_field(value: &serde_json::Value, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(serde_json::Value::as_u64))
}

fn location_label(file: &str, line: Option<u64>) -> String {
    line.map(|line| format!("{file}:{line}"))
        .unwrap_or_else(|| file.to_string())
}

fn run_revision_label(run_state: JsonFileState) -> String {
    run_target_git_from_state(run_state)
        .map(|git| target_git_revision_label(&git))
        .unwrap_or_else(|| "rev:unknown".to_string())
}

fn run_status_label(run_state: JsonFileState) -> String {
    run_status_from_state(run_state).unwrap_or_else(|| "unknown".to_string())
}

fn run_target_git_from_state(state: JsonFileState) -> Option<RunTargetGitMetadata> {
    let JsonFileState::Present(value) = state else {
        return None;
    };
    value
        .get("targetGit")
        .or_else(|| value.get("target_git"))
        .and_then(|git| serde_json::from_value::<RunTargetGitMetadata>(git.clone()).ok())
}

fn run_status_from_state(state: JsonFileState) -> Option<String> {
    let JsonFileState::Present(value) = state else {
        return None;
    };
    string_field(&value, &["status", "runStatus", "run_status"]).map(normalized_run_status_label)
}

fn normalized_run_status_label(status: &str) -> String {
    status.trim().to_ascii_lowercase()
}

fn target_git_revision_label(git: &RunTargetGitMetadata) -> String {
    let short = git.sha.chars().take(7).collect::<String>();
    let dirty = if git.dirty { "*" } else { "" };
    if short.is_empty() {
        "rev:unknown".to_string()
    } else {
        format!("rev:{short}{dirty}")
    }
}

mod assessment;

#[cfg(test)]
mod tests;

use super::ui_run_dir;
use crate::app::JsonFileState;
use crate::ShellApp;
use kuzushi_core::RunTargetGitMetadata;
use std::collections::BTreeMap;
use std::path::Path;

const FINDINGS_FILE: &str = "findings.json";
const RUN_FILE: &str = "run.json";
const SUMMARY_FILE: &str = "summary.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunDiffModel {
    pub(crate) left_run: String,
    pub(crate) right_run: String,
    pub(crate) left_revision: String,
    pub(crate) right_revision: String,
    pub(crate) added: Vec<RunDiffFindingRow>,
    pub(crate) removed: Vec<RunDiffFindingRow>,
    pub(crate) unchanged_count: usize,
    pub(crate) warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunDiffFindingRow {
    pub(crate) key: String,
    pub(crate) title: String,
    pub(crate) severity: String,
    pub(crate) location: String,
    pub(crate) tool: String,
}

pub(crate) fn run_diff_model(app: &ShellApp, left: &str, right: &str) -> RunDiffModel {
    let left_dir = ui_run_dir(app.target.as_deref(), left);
    let right_dir = ui_run_dir(app.target.as_deref(), right);
    let mut warnings = Vec::new();
    let left_findings = load_run_findings(app, &left_dir, left, &mut warnings);
    let right_findings = load_run_findings(app, &right_dir, right, &mut warnings);
    let added = right_findings
        .iter()
        .filter(|(key, _)| !left_findings.contains_key(*key))
        .map(|(_, row)| row.clone())
        .collect();
    let removed = left_findings
        .iter()
        .filter(|(key, _)| !right_findings.contains_key(*key))
        .map(|(_, row)| row.clone())
        .collect();
    let unchanged_count = right_findings
        .keys()
        .filter(|key| left_findings.contains_key(*key))
        .count();

    RunDiffModel {
        left_run: left.to_string(),
        right_run: right.to_string(),
        left_revision: run_revision_label(app, &left_dir),
        right_revision: run_revision_label(app, &right_dir),
        added,
        removed,
        unchanged_count,
        warnings,
    }
}

fn load_run_findings(
    app: &ShellApp,
    run_dir: &Path,
    run_id: &str,
    warnings: &mut Vec<String>,
) -> BTreeMap<String, RunDiffFindingRow> {
    let path = run_dir.join(FINDINGS_FILE);
    let value = match app.workbench_cache.borrow_mut().json_file(&path) {
        JsonFileState::Present(value) => value,
        JsonFileState::Missing => {
            warnings.push(format!("{run_id}: missing {FINDINGS_FILE}"));
            return BTreeMap::new();
        }
        JsonFileState::NonFile | JsonFileState::Malformed | JsonFileState::Unreadable => {
            warnings.push(format!("{run_id}: malformed {FINDINGS_FILE}"));
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
        severity: string_field(value, &["severity", "rank"])
            .unwrap_or("unknown")
            .to_string(),
        location: location_label(file, line),
        tool: string_field(value, &["tool", "source"])
            .unwrap_or("-")
            .to_string(),
    })
}

fn finding_key(value: &serde_json::Value) -> Option<String> {
    string_field(value, &["fingerprint", "id", "dedupKey", "dedup_key"])
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

fn string_field<'a>(value: &'a serde_json::Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(serde_json::Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn integer_field(value: &serde_json::Value, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(serde_json::Value::as_u64))
}

fn location_label(file: &str, line: Option<u64>) -> String {
    line.map(|line| format!("{file}:{line}"))
        .unwrap_or_else(|| file.to_string())
}

fn run_revision_label(app: &ShellApp, run_dir: &Path) -> String {
    let run_state = app
        .workbench_cache
        .borrow_mut()
        .json_file(&run_dir.join(RUN_FILE));
    if let Some(git) = run_target_git_from_state(run_state) {
        return target_git_revision_label(&git);
    }
    let summary_state = app
        .workbench_cache
        .borrow_mut()
        .json_file(&run_dir.join(SUMMARY_FILE));
    run_target_git_from_state(summary_state)
        .map(|git| target_git_revision_label(&git))
        .unwrap_or_else(|| "rev:unknown".to_string())
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

fn target_git_revision_label(git: &RunTargetGitMetadata) -> String {
    let short = git.sha.chars().take(7).collect::<String>();
    let dirty = if git.dirty { "*" } else { "" };
    if short.is_empty() {
        "rev:unknown".to_string()
    } else {
        format!("rev:{short}{dirty}")
    }
}

#[cfg(test)]
mod tests;

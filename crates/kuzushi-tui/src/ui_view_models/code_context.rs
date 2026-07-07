//! Source-code context for the Workbench center pane when a finding is selected.

use super::findings::{current_finding_for_detail, relativize_location, target_base};
use crate::ShellApp;
use kuzushi_core::Finding;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const CONTEXT_BEFORE: u32 = 8;
const CONTEXT_AFTER: u32 = 14;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CodePaneModel {
    pub(crate) title: String,
    pub(crate) path_label: String,
    pub(crate) rows: Vec<CodePaneRow>,
    pub(crate) empty_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CodePaneRow {
    pub(crate) number: u32,
    pub(crate) text: String,
    pub(crate) highlighted: bool,
    pub(crate) evidence: bool,
}

pub(crate) fn selected_finding_code_model(app: &ShellApp) -> Option<CodePaneModel> {
    let (alias, finding) = current_finding_for_detail(app)?;
    let base = target_base(app);
    Some(CodePaneModel::from_finding(
        app,
        &finding,
        alias.as_deref().unwrap_or("selected"),
        base.as_deref(),
    ))
}

impl CodePaneModel {
    fn from_finding(app: &ShellApp, finding: &Finding, alias: &str, base: Option<&str>) -> Self {
        let source_path = resolve_source_path(app.target.as_deref(), &finding.file_path);
        let path_label = relativize_location(finding.file_path.clone(), base);
        let title = code_title(alias, &path_label, finding.start_line, finding.end_line);
        match app
            .workbench_cache
            .borrow_mut()
            .read_source_file(&source_path)
        {
            Ok(raw) => code_model_from_source(finding, title, path_label, &raw),
            Err(error) => missing_code_model(title, path_label, error),
        }
    }
}

fn code_model_from_source(
    finding: &Finding,
    title: String,
    path_label: String,
    raw: &str,
) -> CodePaneModel {
    let source_lines: Vec<&str> = raw.lines().collect();
    let range = finding_range(finding);
    let evidence_lines = evidence_lines(finding);
    let rows = code_rows(&source_lines, range, &evidence_lines);
    CodePaneModel {
        title,
        path_label,
        empty_hint: rows.is_empty().then(|| "source file is empty".to_string()),
        rows,
    }
}

fn missing_code_model(title: String, path_label: String, error: String) -> CodePaneModel {
    CodePaneModel {
        title,
        empty_hint: Some(format!("could not read source file {path_label}: {error}")),
        path_label,
        rows: Vec::new(),
    }
}

fn resolve_source_path(target: Option<&Path>, reported: &str) -> PathBuf {
    let path = PathBuf::from(reported);
    if path.is_absolute() {
        return path;
    }
    target
        .map(|root| root.join(&path))
        .unwrap_or_else(|| current_dir().join(path))
}

fn current_dir() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn code_title(alias: &str, path: &str, start: u32, end: Option<u32>) -> String {
    format!("CODE · {alias} · {}", location_label(path, start, end))
}

fn location_label(path: &str, start: u32, end: Option<u32>) -> String {
    match end.filter(|line| *line > start) {
        Some(end) => format!("{path}:{start}-{end}"),
        None => format!("{path}:{start}"),
    }
}

fn finding_range(finding: &Finding) -> (u32, u32) {
    let start = finding.start_line.max(1);
    let end = finding.end_line.unwrap_or(start).max(start);
    (start, end)
}

fn evidence_lines(finding: &Finding) -> BTreeSet<u32> {
    finding
        .evidence
        .iter()
        .filter(|evidence| evidence.file_path.is_empty() || evidence.file_path == finding.file_path)
        .filter_map(|evidence| (evidence.line > 0).then_some(evidence.line))
        .collect()
}

fn code_rows(lines: &[&str], range: (u32, u32), evidence: &BTreeSet<u32>) -> Vec<CodePaneRow> {
    let total = lines.len() as u32;
    let Some((first, last)) = visible_line_window(total, range) else {
        return Vec::new();
    };
    (first..=last)
        .filter_map(|number| code_row(lines, number, range, evidence))
        .collect()
}

fn visible_line_window(total: u32, range: (u32, u32)) -> Option<(u32, u32)> {
    if total == 0 {
        return None;
    }
    let first = range.0.saturating_sub(CONTEXT_BEFORE).max(1);
    let last = range.1.saturating_add(CONTEXT_AFTER).min(total);
    Some((first, last.max(first)))
}

fn code_row(
    lines: &[&str],
    number: u32,
    range: (u32, u32),
    evidence: &BTreeSet<u32>,
) -> Option<CodePaneRow> {
    let text = lines.get(number.saturating_sub(1) as usize)?;
    Some(CodePaneRow {
        number,
        text: (*text).to_string(),
        highlighted: number >= range.0 && number <= range.1,
        evidence: evidence.contains(&number),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{FindingEvidence, Severity};

    #[test]
    fn code_model_windows_and_highlights_the_finding_range() {
        let mut finding = Finding::new_semgrep(
            "demo.rule",
            "src/app.rs",
            10,
            Some(11),
            Severity::High,
            "demo",
        );
        finding.evidence = vec![FindingEvidence {
            file_path: "src/app.rs".to_string(),
            line: 9,
            kind: "source".to_string(),
            ..Default::default()
        }];
        let raw = (1..=30)
            .map(|line| format!("line {line}"))
            .collect::<Vec<_>>()
            .join("\n");

        let model =
            code_model_from_source(&finding, "CODE".to_string(), "src/app.rs".to_string(), &raw);

        assert_eq!(model.rows.first().map(|row| row.number), Some(2));
        assert!(model
            .rows
            .iter()
            .any(|row| row.number == 10 && row.highlighted));
        assert!(model
            .rows
            .iter()
            .any(|row| row.number == 11 && row.highlighted));
        assert!(model.rows.iter().any(|row| row.number == 9 && row.evidence));
        assert_eq!(model.empty_hint, None);
    }
}

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::attack_surface::{build_attack_surface_map, AttackSurfaceMap};
use crate::findings::Finding;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiffScope {
    pub files: Vec<PathBuf>,
    pub since_ref: String,
    pub include_worktree: bool,
}

impl DiffScope {
    pub fn contains_path(&self, candidate: &Path) -> bool {
        self.files.iter().any(|path| path == candidate)
    }

    pub fn contains_prefix(&self, prefix: &Path) -> bool {
        self.files.iter().any(|path| path.starts_with(prefix))
    }
}

pub fn git_diff_files(target: &Path, since_ref: &str, include_worktree: bool) -> Result<DiffScope> {
    let trimmed = since_ref.trim();
    anyhow::ensure!(
        !trimmed.is_empty(),
        "diff_scope: since_ref must be non-empty"
    );
    anyhow::ensure!(
        !trimmed
            .chars()
            .any(|c| matches!(c, '\n' | '\0' | ';' | '|' | '`')),
        "diff_scope: since_ref contains forbidden characters"
    );

    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(target).arg("diff").arg("--name-only");
    if include_worktree {
        cmd.arg(trimmed);
    } else {
        cmd.arg(format!("{trimmed}...HEAD"));
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd
        .output()
        .with_context(|| format!("diff_scope: could not invoke git in {}", target.display()))?;
    if !output.status.success() {
        anyhow::bail!(
            "diff_scope: git diff failed (exit {}): {}",
            output
                .status
                .code()
                .map(|code| code.to_string())
                .unwrap_or_else(|| "<signal>".to_string()),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let stdout =
        String::from_utf8(output.stdout).context("diff_scope: git output was not valid UTF-8")?;
    let mut files = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    files.sort();
    files.dedup();

    Ok(DiffScope {
        files,
        since_ref: since_ref.to_string(),
        include_worktree,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxDiffScopeReport {
    pub diff_base: String,
    pub target: String,
    pub changed_files: Vec<ChangedFile>,
    pub context: Vec<DiffContext>,
    pub finding_tags: Vec<DiffFindingTag>,
    pub fixed_findings: Vec<DiffFindingTag>,
    pub summary: DiffScopeSummary,
    pub deterministic: bool,
    pub no_remote_provider_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChangedFile {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_path: Option<String>,
    pub status: DiffFileStatus,
    pub changed_ranges: Vec<ChangedLineRange>,
    pub deleted_ranges: Vec<ChangedLineRange>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum DiffFileStatus {
    Added,
    Modified,
    Deleted,
    Renamed,
    Copied,
    TypeChanged,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChangedLineRange {
    pub start_line: u32,
    pub end_line: u32,
    pub kind: DiffRangeKind,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum DiffRangeKind {
    Added,
    Modified,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiffContext {
    pub kind: DiffContextKind,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    pub detail: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DiffContextKind {
    ChangedFile,
    Route,
    Caller,
    Callee,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiffFindingTag {
    pub fingerprint: String,
    pub rule_id: String,
    pub file_path: String,
    pub start_line: u32,
    pub status: DiffFindingStatus,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum DiffFindingStatus {
    New,
    Existing,
    Fixed,
    ChangedContext,
}

impl DiffFindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Existing => "existing",
            Self::Fixed => "fixed",
            Self::ChangedContext => "changed-context",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiffScopeSummary {
    pub changed_files: usize,
    pub changed_ranges: usize,
    pub deleted_ranges: usize,
    pub context_items: usize,
    pub new_findings: usize,
    pub existing_findings: usize,
    pub fixed_findings: usize,
    pub changed_context_findings: usize,
}

pub fn build_whitebox_diff_scope_report(
    root: impl AsRef<Path>,
    diff_base: &str,
    current_findings: &[Finding],
    previous_findings: &[Finding],
) -> Result<WhiteboxDiffScopeReport> {
    let root = root
        .as_ref()
        .canonicalize()
        .with_context(|| format!("repository root {} does not exist", root.as_ref().display()))?;
    if !root.is_dir() {
        anyhow::bail!("repository root {} is not a directory", root.display());
    }

    let changed_files = collect_changed_files(&root, diff_base)?;
    let attack_surface = build_attack_surface_map(&root).ok();
    let context = expand_diff_context(&root, &changed_files, attack_surface.as_ref())?;
    let finding_tags = current_findings
        .iter()
        .map(|finding| tag_current_finding(finding, &changed_files))
        .collect::<Vec<_>>();
    let fixed_findings = tag_fixed_findings(previous_findings, current_findings, &changed_files);
    let summary = summarize_diff_scope(&changed_files, &context, &finding_tags, &fixed_findings);

    Ok(WhiteboxDiffScopeReport {
        diff_base: diff_base.to_string(),
        target: root.display().to_string(),
        changed_files,
        context,
        finding_tags,
        fixed_findings,
        summary,
        deterministic: true,
        no_remote_provider_required: true,
    })
}

fn collect_changed_files(root: &Path, diff_base: &str) -> Result<Vec<ChangedFile>> {
    verify_diff_base(root, diff_base)?;
    let mut files = parse_name_status(&git_output(
        root,
        &[
            "diff",
            "--name-status",
            "--find-renames",
            &format!("{diff_base}...HEAD"),
        ],
    )?);
    parse_unified_diff_ranges(
        &git_output(
            root,
            &[
                "diff",
                "--unified=0",
                "--no-color",
                "--no-ext-diff",
                "--find-renames",
                &format!("{diff_base}...HEAD"),
            ],
        )?,
        &mut files,
    );

    Ok(files.into_values().collect())
}

fn verify_diff_base(root: &Path, diff_base: &str) -> Result<()> {
    let output = Command::new("git")
        .args(["rev-parse", "--verify", diff_base])
        .current_dir(root)
        .output()
        .with_context(|| {
            "whitebox-static diff mode requires local git; install git or omit diffBase"
        })?;
    if !output.status.success() {
        anyhow::bail!(
            "whitebox-static diff mode could not resolve diffBase {:?}: {}",
            diff_base,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn git_output(root: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .with_context(|| {
            "whitebox-static diff mode requires local git; install git or omit diffBase"
        })?;
    if !output.status.success() {
        anyhow::bail!(
            "whitebox-static diff mode git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn parse_name_status(output: &str) -> BTreeMap<String, ChangedFile> {
    let mut files = BTreeMap::new();
    for line in output.lines() {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() < 2 {
            continue;
        }
        let code = fields[0];
        let status = status_from_name_status(code);
        let (previous_path, path) =
            if matches!(status, DiffFileStatus::Renamed | DiffFileStatus::Copied)
                && fields.len() >= 3
            {
                (
                    Some(normalize_repo_path(fields[1])),
                    normalize_repo_path(fields[2]),
                )
            } else {
                (None, normalize_repo_path(fields[1]))
            };
        files.insert(
            path.clone(),
            ChangedFile {
                path,
                previous_path,
                status,
                changed_ranges: Vec::new(),
                deleted_ranges: Vec::new(),
            },
        );
    }
    files
}

fn status_from_name_status(code: &str) -> DiffFileStatus {
    match code.chars().next().unwrap_or(' ') {
        'A' => DiffFileStatus::Added,
        'M' => DiffFileStatus::Modified,
        'D' => DiffFileStatus::Deleted,
        'R' => DiffFileStatus::Renamed,
        'C' => DiffFileStatus::Copied,
        'T' => DiffFileStatus::TypeChanged,
        _ => DiffFileStatus::Unknown,
    }
}

fn parse_unified_diff_ranges(output: &str, files: &mut BTreeMap<String, ChangedFile>) {
    let mut old_path: Option<String> = None;
    let mut new_path: Option<String> = None;
    for line in output.lines() {
        if line.starts_with("diff --git ") {
            old_path = None;
            new_path = None;
            continue;
        }
        if let Some(raw) = line.strip_prefix("--- ") {
            old_path = parse_diff_path(raw);
            continue;
        }
        if let Some(raw) = line.strip_prefix("+++ ") {
            new_path = parse_diff_path(raw);
            continue;
        }
        if !line.starts_with("@@ ") {
            continue;
        }
        let Some((old_start, old_count, new_start, new_count)) = parse_hunk_header(line) else {
            continue;
        };
        let key = new_path
            .as_ref()
            .or(old_path.as_ref())
            .cloned()
            .unwrap_or_default();
        if key.is_empty() {
            continue;
        }
        let file = files.entry(key.clone()).or_insert_with(|| ChangedFile {
            path: key,
            previous_path: old_path.clone(),
            status: DiffFileStatus::Unknown,
            changed_ranges: Vec::new(),
            deleted_ranges: Vec::new(),
        });
        if new_count > 0 {
            file.changed_ranges.push(ChangedLineRange {
                start_line: new_start,
                end_line: new_start + new_count - 1,
                kind: if old_count == 0 {
                    DiffRangeKind::Added
                } else {
                    DiffRangeKind::Modified
                },
            });
        }
        if old_count > 0 {
            file.deleted_ranges.push(ChangedLineRange {
                start_line: old_start,
                end_line: old_start + old_count - 1,
                kind: if new_count == 0 {
                    DiffRangeKind::Deleted
                } else {
                    DiffRangeKind::Modified
                },
            });
        }
    }

    for file in files.values_mut() {
        file.changed_ranges
            .sort_by_key(|range| (range.start_line, range.end_line, range.kind));
        file.deleted_ranges
            .sort_by_key(|range| (range.start_line, range.end_line, range.kind));
    }
}

fn parse_diff_path(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw == "/dev/null" {
        return None;
    }
    raw.strip_prefix("a/")
        .or_else(|| raw.strip_prefix("b/"))
        .map(normalize_repo_path)
        .or_else(|| Some(normalize_repo_path(raw)))
}

fn parse_hunk_header(line: &str) -> Option<(u32, u32, u32, u32)> {
    let header = line.strip_prefix("@@ ")?.split(" @@").next()?;
    let mut parts = header.split_whitespace();
    let old = parts.next()?.strip_prefix('-')?;
    let new = parts.next()?.strip_prefix('+')?;
    let (old_start, old_count) = parse_hunk_range(old)?;
    let (new_start, new_count) = parse_hunk_range(new)?;
    Some((old_start, old_count, new_start, new_count))
}

fn parse_hunk_range(raw: &str) -> Option<(u32, u32)> {
    if let Some((start, count)) = raw.split_once(',') {
        Some((start.parse().ok()?, count.parse().ok()?))
    } else {
        Some((raw.parse().ok()?, 1))
    }
}

fn expand_diff_context(
    root: &Path,
    changed_files: &[ChangedFile],
    attack_surface: Option<&AttackSurfaceMap>,
) -> Result<Vec<DiffContext>> {
    let mut contexts = BTreeMap::new();
    for file in changed_files {
        insert_context(
            &mut contexts,
            DiffContext {
                kind: DiffContextKind::ChangedFile,
                path: file.path.clone(),
                line: file.changed_ranges.first().map(|range| range.start_line),
                detail: format!("{} changed in PR diff", file.path),
                reason: "changed_file".to_string(),
            },
        );
        if let Some(surface_map) = attack_surface {
            for surface in &surface_map.surfaces {
                if surface.path == file.path && surface_in_changed_context(surface.line, file) {
                    insert_context(
                        &mut contexts,
                        DiffContext {
                            kind: DiffContextKind::Route,
                            path: surface.path.clone(),
                            line: surface.line,
                            detail: surface.title.clone(),
                            reason: "route_or_attack_surface_near_diff".to_string(),
                        },
                    );
                }
            }
        }
        inspect_changed_source_context(root, file, &mut contexts)?;
    }
    Ok(contexts.into_values().collect())
}

fn surface_in_changed_context(line: Option<u32>, file: &ChangedFile) -> bool {
    let Some(line) = line else {
        return true;
    };
    file.changed_ranges
        .iter()
        .any(|range| line_near_range(line, range, 25))
        || file.changed_ranges.is_empty()
}

fn inspect_changed_source_context(
    root: &Path,
    file: &ChangedFile,
    contexts: &mut BTreeMap<String, DiffContext>,
) -> Result<()> {
    let path = root.join(&file.path);
    let Ok(bytes) = fs::read(&path) else {
        return Ok(());
    };
    if bytes.iter().take(4096).any(|byte| *byte == 0) {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&bytes);
    let lines = text.lines().collect::<Vec<_>>();
    for range in &file.changed_ranges {
        let start = range.start_line.saturating_sub(25).max(1);
        let end = (range.end_line + 25).min(u32::try_from(lines.len()).unwrap_or(u32::MAX));
        for line_number in start..=end {
            let Some(line) = lines.get((line_number - 1) as usize) else {
                continue;
            };
            if let Some(detail) = function_or_handler_detail(line) {
                insert_context(
                    contexts,
                    DiffContext {
                        kind: DiffContextKind::Caller,
                        path: file.path.clone(),
                        line: Some(line_number),
                        detail,
                        reason: "caller_or_enclosing_function_near_diff".to_string(),
                    },
                );
            }
        }
        for line_number in range.start_line..=range.end_line {
            let Some(line) = lines.get((line_number - 1) as usize) else {
                continue;
            };
            for callee in callees_in_line(line) {
                insert_context(
                    contexts,
                    DiffContext {
                        kind: DiffContextKind::Callee,
                        path: file.path.clone(),
                        line: Some(line_number),
                        detail: callee,
                        reason: "callee_invoked_on_changed_line".to_string(),
                    },
                );
            }
        }
    }
    Ok(())
}

fn function_or_handler_detail(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let function_like = trimmed.starts_with("function ")
        || trimmed.starts_with("async function ")
        || trimmed.starts_with("def ")
        || trimmed.starts_with("func ")
        || trimmed.starts_with("fn ")
        || trimmed.contains("=>")
        || trimmed.contains(".get(")
        || trimmed.contains(".post(")
        || trimmed.contains(".put(")
        || trimmed.contains(".delete(")
        || trimmed.contains(".patch(");
    function_like.then(|| trimmed.chars().take(160).collect())
}

fn callees_in_line(line: &str) -> Vec<String> {
    let mut callees = BTreeSet::new();
    let bytes = line.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b'(' || index == 0 {
            continue;
        }
        let mut start = index;
        while start > 0 {
            let ch = bytes[start - 1] as char;
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' {
                start -= 1;
            } else {
                break;
            }
        }
        if start == index {
            continue;
        }
        let name = line[start..index].trim_matches('.');
        if is_interesting_callee(name) {
            callees.insert(name.to_string());
        }
    }
    callees.into_iter().take(20).collect()
}

fn is_interesting_callee(name: &str) -> bool {
    if name.len() < 2 {
        return false;
    }
    let normalized = name.rsplit('.').next().unwrap_or(name);
    !matches!(
        normalized,
        "if" | "for"
            | "while"
            | "switch"
            | "catch"
            | "return"
            | "function"
            | "fn"
            | "def"
            | "require"
            | "console"
            | "log"
    )
}

fn insert_context(contexts: &mut BTreeMap<String, DiffContext>, context: DiffContext) {
    let key = format!(
        "{:?}:{}:{:?}:{}",
        context.kind, context.path, context.line, context.detail
    );
    contexts.entry(key).or_insert(context);
}

fn tag_current_finding(finding: &Finding, changed_files: &[ChangedFile]) -> DiffFindingTag {
    let Some(file) = changed_files
        .iter()
        .find(|file| file.path == finding.file_path)
    else {
        return diff_finding_tag(
            finding,
            DiffFindingStatus::Existing,
            "finding is outside changed files",
        );
    };
    let end_line = finding.end_line.unwrap_or(finding.start_line);
    if file.status == DiffFileStatus::Added
        || ranges_overlap(finding.start_line, end_line, &file.changed_ranges)
    {
        return diff_finding_tag(
            finding,
            DiffFindingStatus::New,
            "finding source span overlaps PR changed lines",
        );
    }
    diff_finding_tag(
        finding,
        DiffFindingStatus::ChangedContext,
        "finding is in a changed file but outside changed lines",
    )
}

fn tag_fixed_findings(
    previous_findings: &[Finding],
    current_findings: &[Finding],
    changed_files: &[ChangedFile],
) -> Vec<DiffFindingTag> {
    let current = current_findings
        .iter()
        .map(|finding| finding.fingerprint.as_str())
        .collect::<BTreeSet<_>>();
    let mut fixed = Vec::new();
    let mut seen = BTreeSet::new();
    for finding in previous_findings {
        if current.contains(finding.fingerprint.as_str()) || !seen.insert(&finding.fingerprint) {
            continue;
        }
        let Some(file) = changed_files.iter().find(|file| {
            file.path == finding.file_path
                || file.previous_path.as_deref() == Some(finding.file_path.as_str())
        }) else {
            continue;
        };
        let end_line = finding.end_line.unwrap_or(finding.start_line);
        if file.status == DiffFileStatus::Deleted
            || ranges_overlap(finding.start_line, end_line, &file.deleted_ranges)
        {
            fixed.push(diff_finding_tag(
                finding,
                DiffFindingStatus::Fixed,
                "previous finding no longer appears and its old source span was changed or deleted",
            ));
        }
    }
    fixed
}

fn diff_finding_tag(finding: &Finding, status: DiffFindingStatus, reason: &str) -> DiffFindingTag {
    DiffFindingTag {
        fingerprint: finding.fingerprint.clone(),
        rule_id: finding.rule_id.clone(),
        file_path: finding.file_path.clone(),
        start_line: finding.start_line,
        status,
        reason: reason.to_string(),
    }
}

fn summarize_diff_scope(
    changed_files: &[ChangedFile],
    context: &[DiffContext],
    finding_tags: &[DiffFindingTag],
    fixed_findings: &[DiffFindingTag],
) -> DiffScopeSummary {
    let mut summary = DiffScopeSummary {
        changed_files: changed_files.len(),
        changed_ranges: changed_files
            .iter()
            .map(|file| file.changed_ranges.len())
            .sum(),
        deleted_ranges: changed_files
            .iter()
            .map(|file| file.deleted_ranges.len())
            .sum(),
        context_items: context.len(),
        fixed_findings: fixed_findings.len(),
        ..DiffScopeSummary::default()
    };
    for tag in finding_tags {
        match tag.status {
            DiffFindingStatus::New => summary.new_findings += 1,
            DiffFindingStatus::Existing => summary.existing_findings += 1,
            DiffFindingStatus::Fixed => summary.fixed_findings += 1,
            DiffFindingStatus::ChangedContext => summary.changed_context_findings += 1,
        }
    }
    summary
}

fn ranges_overlap(start: u32, end: u32, ranges: &[ChangedLineRange]) -> bool {
    ranges
        .iter()
        .any(|range| start <= range.end_line && end >= range.start_line)
}

fn line_near_range(line: u32, range: &ChangedLineRange, distance: u32) -> bool {
    line >= range.start_line.saturating_sub(distance) && line <= range.end_line + distance
}

fn normalize_repo_path(path: &str) -> String {
    path.trim_matches('"').replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    use tempfile::tempdir;

    use super::*;
    use crate::findings::{Severity, StaticProofState};

    #[cfg(unix)]
    fn init_git_repo(dir: &Path) {
        for args in [
            vec!["init"],
            vec!["config", "user.email", "kuzushi@example.test"],
            vec!["config", "user.name", "Kuzushi Test"],
            vec!["add", "."],
            vec!["commit", "-m", "base"],
        ] {
            let output = Command::new("git")
                .args(args)
                .current_dir(dir)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn git_diff_files_returns_committed_changes() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("a.c"), "void a(){}\n").unwrap();
        init_git_repo(temp.path());
        let base = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(temp.path())
            .output()
            .unwrap();
        assert!(base.status.success());
        let base = String::from_utf8(base.stdout).unwrap().trim().to_string();

        fs::write(temp.path().join("a.c"), "void a2(){}\n").unwrap();
        fs::write(temp.path().join("b.c"), "void b(){}\n").unwrap();
        let output = Command::new("git")
            .args(["add", "."])
            .current_dir(temp.path())
            .output()
            .unwrap();
        assert!(output.status.success());
        let output = Command::new("git")
            .args(["commit", "-m", "change"])
            .current_dir(temp.path())
            .output()
            .unwrap();
        assert!(output.status.success());

        let scope = git_diff_files(temp.path(), &base, false).unwrap();
        assert_eq!(
            scope.files,
            vec![PathBuf::from("a.c"), PathBuf::from("b.c")]
        );
        assert!(scope.contains_path(Path::new("a.c")));
    }

    #[cfg(unix)]
    #[test]
    fn git_diff_files_rejects_ref_injection_chars() {
        let temp = tempdir().unwrap();
        for value in ["abc; rm -rf /", "abc | cat", "abc`whoami`"] {
            let err = git_diff_files(temp.path(), value, false)
                .unwrap_err()
                .to_string();
            assert!(err.contains("forbidden characters"), "{err}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn whitebox_diff_scope_computes_ranges_context_and_finding_tags() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/app.js"),
            [
                "const express = require('express');",
                "const app = express();",
                "app.get('/users', function users(req, res) {",
                "  const id = req.query.id;",
                "  const sql = `select * from users where id = ${id}`;",
                "  eval(req.query.cmd);",
                "  return res.send('ok');",
                "});",
            ]
            .join("\n"),
        )
        .unwrap();
        fs::write(temp.path().join("README.md"), "base\n").unwrap();
        init_git_repo(temp.path());
        fs::write(
            temp.path().join("src/app.js"),
            [
                "const express = require('express');",
                "const app = express();",
                "app.get('/users', function users(req, res) {",
                "  const id = req.query.id;",
                "  const sql = `select * from users where id = ${id}`;",
                "  db.query(sql);",
                "  return res.send('ok');",
                "});",
            ]
            .join("\n"),
        )
        .unwrap();
        fs::write(temp.path().join("README.md"), "base\nchanged\n").unwrap();
        let output = Command::new("git")
            .args(["add", "."])
            .current_dir(temp.path())
            .output()
            .unwrap();
        assert!(output.status.success());
        let output = Command::new("git")
            .args(["commit", "-m", "pr"])
            .current_dir(temp.path())
            .output()
            .unwrap();
        assert!(output.status.success());

        let mut new_finding = Finding::new_tool(
            "codeql",
            "js/sql-injection",
            "src/app.js",
            6,
            Some(6),
            Severity::High,
            "SQL query uses request input",
        );
        new_finding.set_static_proof_state(StaticProofState::SourceSinkLinked);
        let context_finding = Finding::new_tool(
            "semgrep",
            "js/headers",
            "src/app.js",
            2,
            Some(2),
            Severity::Low,
            "Header setup needs review",
        );
        let old_fixed = Finding::new_tool(
            "semgrep",
            "js/missing-query",
            "src/app.js",
            6,
            Some(6),
            Severity::Medium,
            "Previous finding on old changed line",
        );

        let report = build_whitebox_diff_scope_report(
            temp.path(),
            "HEAD~1",
            &[new_finding.clone(), context_finding.clone()],
            &[old_fixed],
        )
        .unwrap();

        assert_eq!(report.no_remote_provider_required, true);
        assert_eq!(report.summary.changed_files, 2);
        assert!(report
            .changed_files
            .iter()
            .any(|file| file.path == "src/app.js" && !file.changed_ranges.is_empty()));
        assert!(report.context.iter().any(|item| {
            item.kind == DiffContextKind::Route
                && item.path == "src/app.js"
                && item.detail.contains("/users")
        }));
        assert!(report.context.iter().any(|item| {
            item.kind == DiffContextKind::Caller && item.detail.contains("function users")
        }));
        assert!(report.context.iter().any(|item| {
            item.kind == DiffContextKind::Callee && item.detail.contains("db.query")
        }));
        assert_eq!(
            report
                .finding_tags
                .iter()
                .find(|tag| tag.fingerprint == new_finding.fingerprint)
                .map(|tag| tag.status),
            Some(DiffFindingStatus::New)
        );
        assert_eq!(
            report
                .finding_tags
                .iter()
                .find(|tag| tag.fingerprint == context_finding.fingerprint)
                .map(|tag| tag.status),
            Some(DiffFindingStatus::ChangedContext)
        );
        assert_eq!(report.fixed_findings.len(), 1);
        assert_eq!(report.fixed_findings[0].status, DiffFindingStatus::Fixed);
    }
}

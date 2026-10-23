//! Bounded, line-addressed code evidence over the same selected target as Map.

use super::{BuildInput, ToolExecutionContext};
use crate::attack_surface::AttackSurface;
use anyhow::{Context, Result};
use model::{Candidate, CodeReport};
use std::collections::BTreeMap;
use std::path::Path;

mod excerpts;
mod model;
mod scoped;
mod selection;
pub(crate) use scoped::{collect_context_files, collect_scoped_source};
#[cfg(test)]
mod tests;

pub(crate) use model::CodeEvidence;
pub(crate) use model::CodeSource;

const MAX_READ_BYTES: usize = 16 * 1024 * 1024;
const MAX_FILE_BYTES: usize = 2 * 1024 * 1024;
const REPORT_RESERVE_BYTES: usize = 256;

pub(crate) fn collect_regeneration_source(
    roots: super::ThreatModelBuildRoots,
    max_source_bytes: usize,
    context_limit: usize,
    ctx: &ToolExecutionContext<'_>,
) -> Result<(String, bool)> {
    let input = BuildInput {
        roots,
        max_source_bytes,
        context_limit,
        ..Default::default()
    };
    let source = collect_source_code(&input, &[], None, ctx)?;
    Ok((source.content, source.partial))
}

pub(super) fn collect_source_code(
    input: &BuildInput,
    surfaces: &[AttackSurface],
    expected_tree_hash: Option<&str>,
    ctx: &ToolExecutionContext<'_>,
) -> Result<CodeSource> {
    anyhow::ensure!(input.max_source_bytes >= 1024, "source-code requires maxSourceBytes >= 1024; increase the budget or select sources without source-code");
    ensure_not_cancelled(ctx)?;
    let tree_hash = current_tree_hash(input.analysis_root())?;
    authenticate_tree(expected_tree_hash, &tree_hash)?;
    let inventory = crate::repository_inventory::build_repository_inventory_with_observer(
        input.analysis_root(),
        &mut |_| {},
        &|| {
            ctx.cancellation
                .is_some_and(crate::scan::ScanCancellation::is_cancelled)
        },
    )?;
    ensure_not_cancelled(ctx)?;
    anyhow::ensure!(
        inventory.truncation.is_none(),
        "source-code requires a complete source-file inventory; narrow the selected scope"
    );
    let selected = selection::select_files(input, inventory, surfaces)?;
    let mut report = new_report(input, tree_hash, &selected);
    collect_selected_files(input, &selected.files, &mut report, ctx)?;
    authenticate_tree(
        Some(&report.tree_hash),
        &current_tree_hash(input.analysis_root())?,
    )?;
    finish_report(report, input.max_source_bytes)
}

fn new_report(input: &BuildInput, tree_hash: String, selected: &model::Selection) -> CodeReport {
    CodeReport {
        policy: "bounded-source-code-v1",
        scope_path: selected.scope_path.clone(),
        tree_hash,
        byte_budget: input.max_source_bytes,
        file_limit: input.context_limit.min(2_000),
        eligible_files: selected.eligible,
        selected_files: selected.files.len(),
        read_bytes: 0,
        omissions: BTreeMap::new(),
        files: Vec::new(),
    }
}

fn collect_selected_files(
    input: &BuildInput,
    selected: &[Candidate],
    report: &mut CodeReport,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    let framing = serde_json::to_vec(report)?.len() + REPORT_RESERVE_BYTES;
    let mut remaining = input.max_source_bytes.saturating_sub(framing);
    let mut weight: usize = selected.iter().map(candidate_weight).sum();
    for candidate in selected {
        ensure_not_cancelled(ctx)?;
        let quota = remaining.saturating_mul(candidate_weight(candidate)) / weight.max(1);
        weight = weight.saturating_sub(candidate_weight(candidate));
        let charged = collect_file(input.analysis_root(), candidate, quota, report)?;
        remaining = remaining.saturating_sub(charged);
    }
    Ok(())
}

fn candidate_weight(candidate: &Candidate) -> usize {
    if candidate.anchors.is_empty() {
        1
    } else {
        4
    }
}

fn collect_file(
    root: &Path,
    candidate: &Candidate,
    quota: usize,
    report: &mut CodeReport,
) -> Result<usize> {
    if quota < 256 {
        report.omit("projection byte budget");
        return Ok(0);
    }
    let Some(raw) = read_code_file(root, candidate, report)? else {
        return Ok(0);
    };
    let Some(file) = excerpts::excerpt(candidate, &raw, quota)? else {
        report.omit("projection byte budget");
        return Ok(0);
    };
    let charged = serde_json::to_vec(&file)?.len() + 1;
    report.files.push(file);
    Ok(charged)
}

fn read_code_file(
    root: &Path,
    candidate: &Candidate,
    report: &mut CodeReport,
) -> Result<Option<String>> {
    let path = root.join(&candidate.path);
    let metadata = std::fs::symlink_metadata(&path)
        .with_context(|| format!("source-code cannot inspect {}", candidate.path))?;
    anyhow::ensure!(
        metadata.is_file(),
        "source-code {} is no longer a regular file",
        candidate.path
    );
    let bound = MAX_FILE_BYTES.min(MAX_READ_BYTES.saturating_sub(report.read_bytes));
    if metadata.len() > bound as u64 {
        report.omit("source read ceiling");
        return Ok(None);
    }
    let bytes = crate::bounded_file::read_regular_bytes_within(root, &path, bound)
        .with_context(|| format!("source-code cannot read {}", candidate.path))?;
    report.read_bytes += bytes.len();
    decode_source(bytes, report)
}

fn decode_source(bytes: Vec<u8>, report: &mut CodeReport) -> Result<Option<String>> {
    if bytes.contains(&0) {
        report.omit("binary source");
        return Ok(None);
    }
    match String::from_utf8(bytes) {
        Ok(text) => Ok(Some(text)),
        Err(_) => {
            report.omit("non-UTF-8 source");
            Ok(None)
        }
    }
}

fn finish_report(report: CodeReport, budget: usize) -> Result<CodeSource> {
    let content = serde_json::to_string(&report)?;
    anyhow::ensure!(content.len() <= budget, "source-code metadata exceeds maxSourceBytes; increase the budget or narrow the selected scope");
    Ok(CodeSource {
        partial: report.partial(),
        references: report.references(),
        content,
    })
}

fn ensure_not_cancelled(ctx: &ToolExecutionContext<'_>) -> Result<()> {
    anyhow::ensure!(
        !ctx.cancellation
            .is_some_and(crate::scan::ScanCancellation::is_cancelled),
        "source-code collection cancelled"
    );
    Ok(())
}

fn current_tree_hash(root: &Path) -> Result<String> {
    crate::incremental_index::current_workspace_tree_hash(root)
        .context("source-code cannot authenticate the selected target")
}

fn authenticate_tree(expected: Option<&str>, actual: &str) -> Result<()> {
    anyhow::ensure!(expected.is_none_or(|expected| expected == actual), "source-code target bytes differ from grounded context; rebuild context before generating a model");
    Ok(())
}

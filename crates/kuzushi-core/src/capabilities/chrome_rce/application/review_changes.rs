use crate::capabilities::chrome_rce::adapters::compare_committed_paths;
use crate::capabilities::chrome_rce::domain::{
    review_hint, ChangedPathLimits, CommittedPathComparison,
};
use crate::ScanCancellation;
use anyhow::Result;
use serde_json::{json, Value};
use std::path::Path;

pub(crate) fn run_review_trigger(
    target: &Path,
    diff_base: Option<&str>,
    limits: ChangedPathLimits,
    cancellation: Option<&ScanCancellation>,
) -> Result<Value> {
    let Some(diff_base) = diff_base else {
        let summary = "Changed-path review skipped: choose diffBase to compare committed paths.";
        return Ok(crate::module_result::skipped_output_result(
            summary,
            summary,
            Vec::new(),
            json!({"target":target,"count":0,"findings":[],"reviewHints":[],"persisted":null}),
        ));
    };
    let comparison = compare_committed_paths(target, diff_base, limits, cancellation)?;
    review_response(target, diff_base, comparison, limits)
}

fn review_response(
    target: &Path,
    diff_base: &str,
    comparison: CommittedPathComparison,
    limits: ChangedPathLimits,
) -> Result<Value> {
    let hints: Vec<_> = comparison
        .changed_files
        .iter()
        .filter_map(|path| review_hint(path, &comparison.repository_prefix))
        .collect();
    let summary = format!(
        "Changed-path review hints: {}{}",
        hints.len(),
        if comparison.omitted_changed_files > 0 {
            "; partial path list"
        } else {
            "; source review required"
        }
    );
    let output = render_comparison(&comparison, &summary, &hints);
    let data = review_data(target, diff_base, &comparison, limits, &hints)?;
    if comparison.omitted_changed_files > 0 {
        let warning = format!(
            "{} changed file paths omitted; review patterns in omitted paths were not assessed.",
            comparison.omitted_changed_files
        );
        return Ok(crate::module_result::partial_output_result(
            summary,
            output,
            vec![json!(warning)],
            data,
        ));
    }
    Ok(crate::module_result::completed_output_result(
        summary, output, data,
    ))
}

fn review_data(
    target: &Path,
    diff_base: &str,
    comparison: &CommittedPathComparison,
    limits: ChangedPathLimits,
    hints: &[crate::capabilities::chrome_rce::domain::ChangedPathReviewHint],
) -> Result<Value> {
    let mut data = serde_json::to_value(comparison)?;
    let fields = json!({"target":target,"diffBase":diff_base,"count":hints.len(),"countKind":"review-hints",
        "reviewHints":hints,"findings":[],"persisted":null,"comparison":"merge-base-to-head",
        "workingTreeExcluded":true,"changedFilesRelativeTo":"selected-target","limits":limits});
    data.as_object_mut()
        .expect("comparison serializes to an object")
        .extend(
            fields
                .as_object()
                .expect("review fields are an object")
                .clone(),
        );
    Ok(data)
}

fn append_review_hints(
    lines: &mut Vec<String>,
    hints: &[crate::capabilities::chrome_rce::domain::ChangedPathReviewHint],
) {
    for hint in hints.iter().take(32) {
        lines.push(format!("Review path: {:?}", hint.file_path));
        lines.push(hint.reason.into());
    }
    if hints.len() > 32 {
        lines.push(format!("Showing 32 of {} review hints. The saved result retains the complete reviewHints list.", hints.len()));
    }
}

fn append_retained_paths(lines: &mut Vec<String>, comparison: &CommittedPathComparison) {
    lines.extend([String::new(), "RETAINED PATHS".into()]);
    lines.extend(
        comparison
            .changed_files
            .iter()
            .take(32)
            .map(|path| format!("Path: {path:?}")),
    );
    if comparison.changed_files.len() > 32 {
        lines.push(format!("Showing 32 of {} retained paths. The saved result retains the complete changedFiles list.", comparison.changed_files.len()));
    }
}

fn render_comparison(
    comparison: &CommittedPathComparison,
    summary: &str,
    hints: &[crate::capabilities::chrome_rce::domain::ChangedPathReviewHint],
) -> String {
    let mut lines = vec![
        summary.to_owned(),
        format!(
            "Changed paths retained: {}/{}; omitted: {}",
            comparison.changed_files.len(),
            comparison.total_changed_files,
            comparison.omitted_changed_files
        ),
        "Vulnerability findings: 0. Review hints need source inspection.".into(),
        "Working-tree, staged and untracked changes are excluded.".into(),
        "No accepted context, scan jobs or phase completion.".into(),
        String::new(),
    ];
    append_review_hints(&mut lines, hints);
    lines.extend([
        String::new(),
        "GIT COMPARISON".into(),
        format!("Requested base commit: {}", comparison.base_commit),
        format!("Actual merge base: {}", comparison.merge_base),
        format!("Compared HEAD: {}", comparison.head_commit),
        format!("Selected-target prefix: {:?}", comparison.repository_prefix),
        "Comparison: merge base to recorded HEAD; path names only.".into(),
        "Path changes establish no vulnerability verdict or fix.".into(),
    ]);
    append_retained_paths(&mut lines, comparison);
    lines.join("\n")
}

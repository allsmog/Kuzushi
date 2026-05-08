use super::*;

pub(in crate::diff_scope) fn summarize_diff_scope(
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

pub(in crate::diff_scope) fn ranges_overlap(
    start: u32,
    end: u32,
    ranges: &[ChangedLineRange],
) -> bool {
    ranges
        .iter()
        .any(|range| start <= range.end_line && end >= range.start_line)
}

pub(in crate::diff_scope) fn line_near_range(
    line: u32,
    range: &ChangedLineRange,
    distance: u32,
) -> bool {
    line >= range.start_line.saturating_sub(distance) && line <= range.end_line + distance
}

pub(in crate::diff_scope) fn normalize_repo_path(path: &str) -> String {
    path.trim_matches('"').replace('\\', "/")
}

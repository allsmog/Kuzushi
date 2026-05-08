use super::*;

pub(in crate::diff_scope) fn status_from_name_status(code: &str) -> DiffFileStatus {
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

pub(in crate::diff_scope) fn parse_unified_diff_ranges(
    output: &str,
    files: &mut BTreeMap<String, ChangedFile>,
) {
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

pub(in crate::diff_scope) fn parse_diff_path(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw == "/dev/null" {
        return None;
    }
    raw.strip_prefix("a/")
        .or_else(|| raw.strip_prefix("b/"))
        .map(normalize_repo_path)
        .or_else(|| Some(normalize_repo_path(raw)))
}

pub(in crate::diff_scope) fn parse_hunk_header(line: &str) -> Option<(u32, u32, u32, u32)> {
    let header = line.strip_prefix("@@ ")?.split(" @@").next()?;
    let mut parts = header.split_whitespace();
    let old = parts.next()?.strip_prefix('-')?;
    let new = parts.next()?.strip_prefix('+')?;
    let (old_start, old_count) = parse_hunk_range(old)?;
    let (new_start, new_count) = parse_hunk_range(new)?;
    Some((old_start, old_count, new_start, new_count))
}

pub(in crate::diff_scope) fn parse_hunk_range(raw: &str) -> Option<(u32, u32)> {
    if let Some((start, count)) = raw.split_once(',') {
        Some((start.parse().ok()?, count.parse().ok()?))
    } else {
        Some((raw.parse().ok()?, 1))
    }
}

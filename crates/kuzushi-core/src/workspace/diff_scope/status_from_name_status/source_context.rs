use super::*;

pub(in crate::workspace::diff_scope) fn inspect_changed_source_context(
    root: &Path,
    file: &ChangedFile,
    contexts: &mut BTreeMap<String, DiffContext>,
) -> Result<()> {
    let Some(lines) = changed_source_lines(root, file) else {
        return Ok(());
    };
    for range in &file.changed_ranges {
        collect_nearby_callers(file, range, &lines, contexts);
        collect_changed_line_callees(file, range, &lines, contexts);
    }
    Ok(())
}

fn changed_source_lines(root: &Path, file: &ChangedFile) -> Option<Vec<String>> {
    let path = root.join(&file.path);
    let bytes =
        crate::bounded_file::read_regular_bytes_within(root, &path, 16 * 1024 * 1024).ok()?;
    if bytes.iter().take(4096).any(|byte| *byte == 0) {
        return None;
    }
    Some(
        String::from_utf8_lossy(&bytes)
            .lines()
            .map(str::to_string)
            .collect(),
    )
}

fn collect_nearby_callers(
    file: &ChangedFile,
    range: &ChangedLineRange,
    lines: &[String],
    contexts: &mut BTreeMap<String, DiffContext>,
) {
    let start = range.start_line.saturating_sub(25).max(1);
    let end = range
        .end_line
        .saturating_add(25)
        .min(u32::try_from(lines.len()).unwrap_or(u32::MAX));
    for line_number in start..=end {
        let Some(detail) = source_line(lines, line_number).and_then(function_or_handler_detail)
        else {
            continue;
        };
        insert_context(contexts, caller_context(file, line_number, detail));
    }
}

fn collect_changed_line_callees(
    file: &ChangedFile,
    range: &ChangedLineRange,
    lines: &[String],
    contexts: &mut BTreeMap<String, DiffContext>,
) {
    for line_number in range.start_line..=range.end_line {
        let Some(line) = source_line(lines, line_number) else {
            continue;
        };
        for callee in callees_in_line(line) {
            insert_context(contexts, callee_context(file, line_number, callee));
        }
    }
}

fn source_line(lines: &[String], line_number: u32) -> Option<&str> {
    lines
        .get(line_number.saturating_sub(1) as usize)
        .map(String::as_str)
}

fn caller_context(file: &ChangedFile, line: u32, detail: String) -> DiffContext {
    DiffContext {
        kind: DiffContextKind::Caller,
        path: file.path.clone(),
        line: Some(line),
        detail,
        reason: "caller_or_enclosing_function_near_diff".to_string(),
    }
}

fn callee_context(file: &ChangedFile, line: u32, detail: String) -> DiffContext {
    DiffContext {
        kind: DiffContextKind::Callee,
        path: file.path.clone(),
        line: Some(line),
        detail,
        reason: "callee_invoked_on_changed_line".to_string(),
    }
}

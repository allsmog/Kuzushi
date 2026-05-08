use super::*;

pub(in crate::diff_scope) fn inspect_changed_source_context(
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

use super::*;

pub(in crate::modules) fn collect_findings(
    root: &Path,
    dir: &Path,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        collect_findings_entry(root, entry, findings)?;
    }
    Ok(())
}

fn collect_findings_entry(
    root: &Path,
    entry: fs::DirEntry,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let path = entry.path();
    if should_skip_path(&entry.file_name().to_string_lossy()) {
        return Ok(());
    }
    let Ok(file_type) = entry.file_type() else {
        return Ok(());
    };
    if file_type.is_dir() {
        return collect_findings(root, &path, findings);
    }
    if file_type.is_file() && is_source_path(root, &path) {
        collect_duplicate_handle_findings(root, &path, findings);
    }
    Ok(())
}

fn collect_duplicate_handle_findings(root: &Path, path: &Path, findings: &mut Vec<Finding>) {
    let raw = fs::read(path).unwrap_or_default();
    if raw.iter().take(4096).any(|byte| *byte == 0) {
        return;
    }
    let text = String::from_utf8_lossy(&raw);
    if !contains_unrejected_duplicate_handle(&text) {
        return;
    }
    push_duplicate_handle_lines(root, path, &text, findings);
}

fn contains_unrejected_duplicate_handle(text: &str) -> bool {
    text.contains("DuplicateHandle")
        && !DUPLICATE_HANDLE_REJECTION_MARKERS
            .iter()
            .any(|marker| text.contains(marker))
}

const DUPLICATE_HANDLE_REJECTION_MARKERS: &[&str] = &[
    "IsPseudoHandle",
    "INVALID_HANDLE_VALUE",
    "IsValidHandleValue",
    "reinterpret_cast<intptr_t>",
];

fn push_duplicate_handle_lines(root: &Path, path: &Path, text: &str, findings: &mut Vec<Finding>) {
    for (index, line) in text.lines().enumerate() {
        if line.contains("DuplicateHandle") {
            findings.push(duplicate_handle_finding(root, path, index));
        }
    }
}

fn duplicate_handle_finding(root: &Path, path: &Path, index: usize) -> Finding {
    Finding::new_tool(
        "chrome-rce",
        "chrome-rce-mojo-broker-pseudohandle-reject",
        path.strip_prefix(root).unwrap_or(path).display().to_string(),
        (index + 1) as u32,
        None,
        Severity::High,
        "::DuplicateHandle is called in a Chrome IPC/broker path without an obvious pseudo-handle reject. Anchored to CVE-2025-2783; reject Win32 pseudo-handles before duplicating peer-supplied handles.",
    )
}

pub(in crate::modules) fn is_source_path(root: &Path, path: &Path) -> bool {
    let ext = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    if !matches!(ext, "c" | "cc" | "cpp" | "cxx" | "h" | "hh" | "hpp") {
        return false;
    }
    let relative = path
        .strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
        .replace('\\', "/");
    relative.contains("/ipc/")
        || relative.contains("/mojo/")
        || relative.contains("/services/")
        || relative.contains("/sandbox/")
        || relative.contains("broker")
}

pub(in crate::modules) fn review_trigger(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step("tool", "review-trigger", "chrome-rce:review-trigger start")
            .emit();
    }
    let Some(diff_base) = string_input_any(&input, &["diffBase", "diff_base"]) else {
        return Ok(json!({
            "ok": true,
            "output": "chrome-rce:review-trigger skipped: pass diffBase to enable PR hot-path review.",
            "data": {
                "target": target.display().to_string(),
                "count": 0,
                "findings": [],
            },
        }));
    };
    let changed = changed_files(&target, &diff_base)?;
    let findings = changed
        .iter()
        .filter_map(|file| hot_path_finding(file))
        .collect::<Vec<_>>();
    let persisted = persist_tool_findings("chrome-rce", &target, &findings, ctx)?;
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "review-trigger",
                format!(
                    "chrome-rce:review-trigger complete · {} hot paths",
                    findings.len()
                ),
            )
            .emit();
    }
    Ok(json!({
        "ok": true,
        "output": format!(
            "chrome-rce:review-trigger matched {} hot path{} vs {}",
            findings.len(),
            if findings.len() == 1 { "" } else { "s" },
            diff_base
        ),
        "data": {
            "target": target.display().to_string(),
            "diffBase": diff_base,
            "changedFiles": changed,
            "count": findings.len(),
            "findings": findings,
            "persisted": persisted,
        },
    }))
}

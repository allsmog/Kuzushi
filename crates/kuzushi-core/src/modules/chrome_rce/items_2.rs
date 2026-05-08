use super::prelude::*;
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
        let path = entry.path();
        let name = entry.file_name();
        if should_skip_path(&name.to_string_lossy()) {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            collect_findings(root, &path, findings)?;
        } else if file_type.is_file() && is_source_path(root, &path) {
            let raw = fs::read(&path).unwrap_or_default();
            if raw.iter().take(4096).any(|byte| *byte == 0) {
                continue;
            }
            let text = String::from_utf8_lossy(&raw);
            if !text.contains("DuplicateHandle") {
                continue;
            }
            if text.contains("IsPseudoHandle")
                || text.contains("INVALID_HANDLE_VALUE")
                || text.contains("IsValidHandleValue")
                || text.contains("reinterpret_cast<intptr_t>")
            {
                continue;
            }
            for (index, line) in text.lines().enumerate() {
                if line.contains("DuplicateHandle") {
                    let relative = path
                        .strip_prefix(root)
                        .unwrap_or(&path)
                        .display()
                        .to_string();
                    findings.push(Finding::new_tool(
                        "chrome-rce",
                        "chrome-rce-mojo-broker-pseudohandle-reject",
                        relative,
                        (index + 1) as u32,
                        None,
                        Severity::High,
                        "::DuplicateHandle is called in a Chrome IPC/broker path without an obvious pseudo-handle reject. Anchored to CVE-2025-2783; reject Win32 pseudo-handles before duplicating peer-supplied handles.",
                    ));
                }
            }
        }
    }
    Ok(())
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

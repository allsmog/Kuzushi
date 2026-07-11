use crate::runtime::{ToolCall, ToolResult};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub(super) fn run_uaf_repo_tool(
    target: &Path,
    include_non_production: bool,
    call: &ToolCall,
) -> ToolResult {
    match call.name.as_str() {
        "grep" => handle_grep(target, include_non_production, call),
        "read_file" => handle_read_file(target, call),
        "list_dir" => handle_list_dir(target, call),
        other => failed_tool_result(
            call,
            json!({"error": format!("uaf-hunt: unknown tool {other:?}")}),
        ),
    }
}

pub(super) fn successful_tool_result(call: &ToolCall, output: Value) -> ToolResult {
    ToolResult {
        call_id: call.call_id.clone(),
        output,
        is_error: false,
    }
}

pub(super) fn failed_tool_result(call: &ToolCall, output: Value) -> ToolResult {
    ToolResult {
        call_id: call.call_id.clone(),
        output,
        is_error: true,
    }
}

fn handle_grep(target: &Path, include_non_production: bool, call: &ToolCall) -> ToolResult {
    grep_output(target, include_non_production, call)
        .map(|output| successful_tool_result(call, output))
        .unwrap_or_else(|err| failed_tool_result(call, json!({"error": format!("grep: {err:#}")})))
}

fn grep_output(target: &Path, include_non_production: bool, call: &ToolCall) -> Result<Value> {
    let pattern = required_string(call, "pattern", "grep: missing or empty `pattern`")?;
    let globs = globs_from_call(call, include_non_production);
    let max_results = max_results_from_call(call);
    run_ripgrep(target, &pattern, &globs, max_results)
}

fn required_string(call: &ToolCall, key: &str, message: &str) -> Result<String> {
    call.input
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!(message.to_string()))
}

fn globs_from_call(call: &ToolCall, include_non_production: bool) -> Vec<String> {
    call.input
        .get("globs")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_else(|| default_c_globs(include_non_production))
}

fn max_results_from_call(call: &ToolCall) -> usize {
    call.input
        .get("maxResults")
        .and_then(Value::as_u64)
        .map(|n| n as usize)
        .unwrap_or(60)
        .clamp(1, 200)
}

fn default_c_globs(include_non_production: bool) -> Vec<String> {
    let mut globs = vec![
        "**/*.c".to_string(),
        "**/*.h".to_string(),
        "**/*.cc".to_string(),
        "**/*.cpp".to_string(),
        "**/*.hpp".to_string(),
    ];
    if !include_non_production {
        globs.extend(non_production_exclude_globs());
    }
    globs
}

fn non_production_exclude_globs() -> Vec<String> {
    [
        "!docs/**",
        "!doc/**",
        "!examples/**",
        "!example/**",
        "!tests/**",
        "!test/**",
        "!fixtures/**",
        "!__tests__/**",
    ]
    .iter()
    .map(|glob| glob.to_string())
    .collect()
}

fn run_ripgrep(
    target: &Path,
    pattern: &str,
    globs: &[String],
    max_results: usize,
) -> Result<Value> {
    let mut cmd = std::process::Command::new("rg");
    cmd.arg("--line-number")
        .arg("--no-heading")
        .arg("--color=never")
        .arg("--max-count")
        .arg(max_results.to_string())
        .arg("--with-filename");
    for glob in globs {
        cmd.arg("--glob").arg(glob);
    }
    cmd.arg("--").arg(pattern).current_dir(target);
    let output = cmd
        .output()
        .context("failed to invoke rg (is ripgrep installed?)")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let matches: Vec<Value> = stdout
        .lines()
        .take(max_results)
        .map(|line| Value::String(line.to_string()))
        .collect();
    Ok(json!({
        "pattern": pattern,
        "matches": matches,
        "count": matches.len(),
    }))
}

fn handle_read_file(target: &Path, call: &ToolCall) -> ToolResult {
    read_file_output(target, call)
        .map(|output| successful_tool_result(call, output))
        .unwrap_or_else(|err| {
            failed_tool_result(call, json!({"error": format!("read_file: {err}")}))
        })
}

fn read_file_output(target: &Path, call: &ToolCall) -> Result<Value> {
    let file = required_string(call, "file", "missing `file`")?;
    let resolved = resolve_repo_path(target, &file)?;
    let raw = crate::bounded_file::read_utf8_text(&resolved, 8 * 1024 * 1024)?;
    let start = read_line_number(call, "startLine").unwrap_or(1).max(1);
    let end = read_line_number(call, "endLine");
    Ok(json!({
        "file": file,
        "startLine": start,
        "endLine": end,
        "content": selected_numbered_lines(&raw, start, end),
    }))
}

fn read_line_number(call: &ToolCall, key: &str) -> Option<usize> {
    call.input.get(key).and_then(Value::as_u64).map(|n| n as usize)
}

fn selected_numbered_lines(raw: &str, start: usize, end: Option<usize>) -> String {
    raw.lines()
        .enumerate()
        .map(|(idx, line)| (idx + 1, line))
        .filter(|(line_no, _)| *line_no >= start && end.map_or(true, |limit| *line_no <= limit))
        .take(800)
        .map(|(line_no, line)| format!("{line_no:>5}: {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn handle_list_dir(target: &Path, call: &ToolCall) -> ToolResult {
    list_dir_output(target, call)
        .map(|output| successful_tool_result(call, output))
        .unwrap_or_else(|err| failed_tool_result(call, json!({"error": format!("list_dir: {err}")})))
}

fn list_dir_output(target: &Path, call: &ToolCall) -> Result<Value> {
    let path = call
        .input
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or(".");
    let resolved = resolve_repo_path(target, path)?;
    Ok(json!({
        "path": path,
        "entries": list_dir_entries(&resolved)?,
    }))
}

fn list_dir_entries(resolved: &Path) -> Result<Vec<String>> {
    Ok(std::fs::read_dir(resolved)?
        .filter_map(|entry| entry.ok())
        .map(|entry| {
            let kind = if entry.path().is_dir() { "dir" } else { "file" };
            format!("{kind} {}", entry.file_name().to_string_lossy())
        })
        .take(200)
        .collect())
}

fn resolve_repo_path(target: &Path, raw: &str) -> Result<PathBuf> {
    let resolved = if Path::new(raw).is_absolute() {
        PathBuf::from(raw)
    } else {
        target.join(raw)
    };
    let canonical_target = std::fs::canonicalize(target)
        .with_context(|| format!("could not canonicalise target {}", target.display()))?;
    let canonical_resolved = std::fs::canonicalize(&resolved)
        .with_context(|| format!("could not canonicalise path {}", resolved.display()))?;
    if !canonical_resolved.starts_with(&canonical_target) {
        anyhow::bail!(
            "path {} escapes workspace root {}",
            canonical_resolved.display(),
            canonical_target.display()
        );
    }
    Ok(canonical_resolved)
}

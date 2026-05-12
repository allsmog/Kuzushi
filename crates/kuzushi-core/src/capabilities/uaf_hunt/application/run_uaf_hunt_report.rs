use crate::capabilities::uaf_hunt::adapters::clang_subprocess::{
    rewrite_unsupported_method_error, ClangMcpClient,
};
use crate::capabilities::uaf_hunt::adapters::parse_uaf_hunt_input;
use crate::capabilities::uaf_hunt::application::{
    build_uaf_hunt_user_prompt, normalize_uaf_hunt_findings, persist_uaf_hunt_findings,
    uaf_hunt_agent_tools, UAF_HUNT_SYSTEM_PROMPT,
};
use crate::capabilities::uaf_hunt::domain::{UafHuntInput, UafHuntReport};
use crate::findings::Finding;
use crate::modules::ToolExecutionContext;
use crate::runtime::{
    run_tool_loop, AgentLoopOutcome, AgentRuntime, AgentToolLoopRequest, LoopHistoryEntry,
    ToolCall, ToolCallHandler, ToolResult,
};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub fn run_uaf_hunt_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<UafHuntReport> {
    let target = resolve_target(input, ctx)?;
    let options = parse_uaf_hunt_input(input, &target)?;
    let runtime = require_runtime(runtime)?;
    if !runtime.supports_tools() {
        anyhow::bail!(
            "uaf-hunt:hunt: configured runtime does not support tool-augmented loops. \
             PiAgentCoreRuntime is required; check the bridge configuration."
        );
    }

    let mut clang = ClangMcpClient::spawn(&target, &options.compile_commands_path)?;
    let clang_stats = Arc::new(Mutex::new(ClangCallStats::default()));
    let toolbox = build_uaf_hunt_toolbox(&target, &mut clang, Arc::clone(&clang_stats));
    let request = build_loop_request(&target, &options, ctx)?;
    let mut handler = toolbox;
    let outcome = run_tool_loop(runtime, &request, &mut handler)
        .context("uaf-hunt: agent tool-loop failed")?;

    let stats = clang_stats.lock().expect("clang stats lock").clone();
    let findings = extract_findings(&outcome, &options)?;
    let persisted = persist_uaf_hunt_findings(&target, &findings, &outcome.transcript, ctx)?;

    Ok(UafHuntReport {
        target: target.display().to_string(),
        count: findings.len(),
        findings,
        persisted,
        compile_commands_path: options.compile_commands_path.display().to_string(),
        clang_tool_calls: stats.calls,
        first_clang_error: stats.first_error,
        steps_used: outcome.steps_used,
        truncated: outcome.truncated,
        cost_usd: outcome.cost_usd,
    })
}

fn resolve_target(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    let resolved = if let Some(raw) = input.get("target").and_then(Value::as_str) {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            current_dir_target()?
        } else {
            let candidate = PathBuf::from(trimmed);
            if candidate.is_absolute() {
                candidate
            } else {
                current_dir_target()?.join(candidate)
            }
        }
    } else if let Some(workspace) = ctx.workspace {
        workspace.root().to_path_buf()
    } else {
        current_dir_target()?
    };
    if !resolved.is_dir() {
        anyhow::bail!(
            "uaf-hunt:hunt: target is not a directory: {}",
            resolved.display()
        );
    }
    Ok(resolved)
}

fn current_dir_target() -> Result<PathBuf> {
    std::env::current_dir().context("uaf-hunt: could not resolve current directory")
}

fn require_runtime(runtime: Option<&dyn AgentRuntime>) -> Result<&dyn AgentRuntime> {
    runtime.ok_or_else(|| {
        anyhow::anyhow!(
            "uaf-hunt:hunt requires an agent runtime; none configured. \
             Set a model with `model anthropic:claude-haiku-4-5` (shell) \
             or `KUZUSHI_MODEL=...` (CLI) before invoking."
        )
    })
}

fn build_loop_request(
    target: &Path,
    options: &UafHuntInput,
    ctx: &ToolExecutionContext<'_>,
) -> Result<AgentToolLoopRequest> {
    let model = options
        .model
        .clone()
        .or_else(|| ctx.config.model.clone())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "uaf-hunt:hunt: no model configured. Pass `model` in the input or set \
                 ctx.config.model via `KUZUSHI_MODEL=anthropic:claude-haiku-4-5`."
            )
        })?;
    Ok(AgentToolLoopRequest {
        model,
        cwd: target.to_path_buf(),
        system_prompt: UAF_HUNT_SYSTEM_PROMPT.to_string(),
        prompt: build_uaf_hunt_user_prompt(options),
        tools: uaf_hunt_agent_tools(),
        max_steps: options.max_agent_steps,
        runtime_options: None,
        temperature: None,
    })
}

fn extract_findings(outcome: &AgentLoopOutcome, options: &UafHuntInput) -> Result<Vec<Finding>> {
    if let Some(structured) = outcome.structured.as_ref() {
        return normalize_uaf_hunt_findings(structured, options.max_findings);
    }
    // The Anthropic next-step path also surfaces a `Final.text` payload
    // when the model wrapped its JSON in prose; try to recover.
    if !outcome.text.is_empty() {
        if let Ok(parsed) = serde_json::from_str::<Value>(outcome.text.trim()) {
            return normalize_uaf_hunt_findings(&parsed, options.max_findings);
        }
        if let Some(parsed) = extract_first_json_object(&outcome.text) {
            return normalize_uaf_hunt_findings(&parsed, options.max_findings);
        }
    }
    // Truncation OR the model surrendered with no structured output:
    // honest empty result.
    Ok(Vec::new())
}

fn extract_first_json_object(text: &str) -> Option<Value> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end <= start {
        return None;
    }
    serde_json::from_str(&text[start..=end]).ok()
}

/// Build the toolbox that handles each agent tool call. The clang
/// tools forward to the long-lived mcp-clang subprocess; the repo
/// tools are handled inline so we don't need to round-trip to a
/// second MCP server.
fn build_uaf_hunt_toolbox<'a>(
    target: &Path,
    clang: &'a mut ClangMcpClient,
    stats: Arc<Mutex<ClangCallStats>>,
) -> UafHuntHandler<'a> {
    UafHuntHandler {
        target: target.to_path_buf(),
        clang: clang as *mut ClangMcpClient,
        stats,
        _marker: std::marker::PhantomData,
    }
}

/// A `ToolCallHandler` that owns a raw pointer to the `ClangMcpClient`
/// living on the stack of `run_uaf_hunt_report`. Safety: the client's
/// lifetime strictly outlives the handler — both are dropped at the
/// end of `run_uaf_hunt_report`, and the tool-loop is single-threaded
/// (one call at a time) so there's no aliasing. We don't use a
/// reference because `ToolCallHandler::run` needs `&mut self` and the
/// client also wants `&mut self`, which would otherwise create nested
/// borrows; the raw pointer is the simplest way to thread the
/// long-lived subprocess through the trait.
struct UafHuntHandler<'a> {
    target: PathBuf,
    clang: *mut ClangMcpClient,
    stats: Arc<Mutex<ClangCallStats>>,
    _marker: std::marker::PhantomData<&'a mut ClangMcpClient>,
}

unsafe impl<'a> Send for UafHuntHandler<'a> {}

#[derive(Debug, Default, Clone)]
struct ClangCallStats {
    calls: u32,
    first_error: Option<String>,
}

impl<'a> ToolCallHandler for UafHuntHandler<'a> {
    fn run(&mut self, call: &ToolCall) -> Result<ToolResult> {
        let name = call.name.as_str();
        if let Some(clang_method) = clang_tool_method(name) {
            // Safety: see comment on `UafHuntHandler`.
            let clang = unsafe { &mut *self.clang };
            self.stats.lock().expect("clang stats lock").calls += 1;
            // mcp-clang tools require a `repoPath` argument the agent
            // shouldn't have to know. Inject it from the host
            // workspace target before forwarding.
            let mut arguments = call.input.clone();
            if let Some(map) = arguments.as_object_mut() {
                if !map.contains_key("repoPath") {
                    map.insert(
                        "repoPath".to_string(),
                        Value::String(self.target.display().to_string()),
                    );
                }
            }
            let result = clang.call_tool(clang_method, arguments);
            let outcome = match result {
                Ok(value) => ToolResult {
                    call_id: call.call_id.clone(),
                    output: value,
                    is_error: false,
                },
                Err(err) => {
                    let formatted = format!("{err:#}");
                    let mut stats = self.stats.lock().expect("clang stats lock");
                    if stats.first_error.is_none() {
                        stats.first_error = Some(formatted.clone());
                    }
                    // Intercept "method not found" failures (clangd 18
                    // doesn't implement outgoingCalls). Return a structured
                    // advisory so the agent learns to fall back to
                    // clang_definition + read_file instead of retrying the
                    // unsupported call.
                    if let Some(advisory) = rewrite_unsupported_method_error(clang_method, &err) {
                        ToolResult {
                            call_id: call.call_id.clone(),
                            output: advisory.to_tool_result(),
                            is_error: false,
                        }
                    } else {
                        ToolResult {
                            call_id: call.call_id.clone(),
                            output: json!({"error": formatted}),
                            is_error: true,
                        }
                    }
                }
            };
            return Ok(outcome);
        }
        match name {
            "grep" => Ok(handle_grep(&self.target, call)),
            "read_file" => Ok(handle_read_file(&self.target, call)),
            "list_dir" => Ok(handle_list_dir(&self.target, call)),
            other => Ok(ToolResult {
                call_id: call.call_id.clone(),
                output: json!({"error": format!("uaf-hunt: unknown tool {other:?}")}),
                is_error: true,
            }),
        }
    }
}

fn clang_tool_method(name: &str) -> Option<&'static str> {
    match name {
        "clang_callers" => Some("clang.callers"),
        "clang_callees" => Some("clang.callees"),
        "clang_references" => Some("clang.references"),
        "clang_definition" => Some("clang.definition"),
        "clang_type_at" => Some("clang.type_at"),
        _ => None,
    }
}

fn handle_grep(target: &Path, call: &ToolCall) -> ToolResult {
    let pattern = match call.input.get("pattern").and_then(Value::as_str) {
        Some(value) if !value.is_empty() => value.to_string(),
        _ => {
            return ToolResult {
                call_id: call.call_id.clone(),
                output: json!({"error": "grep: missing or empty `pattern`"}),
                is_error: true,
            }
        }
    };
    let globs: Vec<String> = call
        .input
        .get("globs")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_else(default_c_globs);
    let max_results = call
        .input
        .get("maxResults")
        .and_then(Value::as_u64)
        .map(|n| n as usize)
        .unwrap_or(60)
        .clamp(1, 200);
    match run_ripgrep(target, &pattern, &globs, max_results) {
        Ok(value) => ToolResult {
            call_id: call.call_id.clone(),
            output: value,
            is_error: false,
        },
        Err(err) => ToolResult {
            call_id: call.call_id.clone(),
            output: json!({"error": format!("grep: {err:#}")}),
            is_error: true,
        },
    }
}

fn default_c_globs() -> Vec<String> {
    vec![
        "**/*.c".to_string(),
        "**/*.h".to_string(),
        "**/*.cc".to_string(),
        "**/*.cpp".to_string(),
        "**/*.hpp".to_string(),
    ]
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
        .context("grep: failed to invoke rg (is ripgrep installed?)")?;
    // ripgrep exits 1 when no matches found — treat as a successful
    // empty result, not an error.
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
    let file = match call.input.get("file").and_then(Value::as_str) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            return ToolResult {
                call_id: call.call_id.clone(),
                output: json!({"error": "read_file: missing `file`"}),
                is_error: true,
            }
        }
    };
    let resolved = match resolve_repo_path(target, &file) {
        Ok(path) => path,
        Err(err) => {
            return ToolResult {
                call_id: call.call_id.clone(),
                output: json!({"error": format!("read_file: {err}")}),
                is_error: true,
            }
        }
    };
    let raw = match std::fs::read_to_string(&resolved) {
        Ok(text) => text,
        Err(err) => {
            return ToolResult {
                call_id: call.call_id.clone(),
                output: json!({"error": format!("read_file: {err}")}),
                is_error: true,
            }
        }
    };
    let start = call
        .input
        .get("startLine")
        .and_then(Value::as_u64)
        .map(|n| n as usize)
        .unwrap_or(1)
        .max(1);
    let end = call
        .input
        .get("endLine")
        .and_then(Value::as_u64)
        .map(|n| n as usize);
    let lines: Vec<String> = raw
        .lines()
        .enumerate()
        .map(|(idx, line)| (idx + 1, line))
        .filter(|(line_no, _)| *line_no >= start && end.map_or(true, |limit| *line_no <= limit))
        .take(800) // hard cap so a 100k-line file doesn't pin the context.
        .map(|(line_no, line)| format!("{line_no:>5}: {line}"))
        .collect();
    ToolResult {
        call_id: call.call_id.clone(),
        output: json!({
            "file": file,
            "startLine": start,
            "endLine": end,
            "content": lines.join("\n"),
        }),
        is_error: false,
    }
}

fn handle_list_dir(target: &Path, call: &ToolCall) -> ToolResult {
    let path = call
        .input
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or(".");
    let resolved = match resolve_repo_path(target, path) {
        Ok(value) => value,
        Err(err) => {
            return ToolResult {
                call_id: call.call_id.clone(),
                output: json!({"error": format!("list_dir: {err}")}),
                is_error: true,
            }
        }
    };
    let entries = match std::fs::read_dir(&resolved) {
        Ok(iter) => iter
            .filter_map(|entry| entry.ok())
            .map(|entry| {
                let kind = if entry.path().is_dir() { "dir" } else { "file" };
                format!("{kind} {}", entry.file_name().to_string_lossy())
            })
            .take(200)
            .collect::<Vec<_>>(),
        Err(err) => {
            return ToolResult {
                call_id: call.call_id.clone(),
                output: json!({"error": format!("list_dir: {err}")}),
                is_error: true,
            }
        }
    };
    ToolResult {
        call_id: call.call_id.clone(),
        output: json!({
            "path": path,
            "entries": entries,
        }),
        is_error: false,
    }
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

// PHANTOM USE: keep `LoopHistoryEntry` in scope so the rustdoc reference
// in the AgentToolLoopRequest comment doesn't break. (Compile no-op.)
#[allow(dead_code)]
fn _unused_history_marker(_entry: LoopHistoryEntry) {}

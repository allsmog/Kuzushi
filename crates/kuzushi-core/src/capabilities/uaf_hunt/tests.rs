use super::adapters::clang_subprocess::rewrite_unsupported_method_error;
use super::adapters::{parse_uaf_hunt_input, resolve_compile_commands_path};
use super::application::run_uaf_hunt_report;
use crate::config::V2Config;
use crate::findings::TriageOutcome;
use crate::modules::ToolExecutionContext;
use crate::runtime::{
    AgentLoopStep, AgentRuntime, AgentToolLoopRequest, LoopHistoryEntry, ToolCall, TriageRequest,
};
use anyhow::Result;
use serde_json::json;
use std::sync::{Mutex, OnceLock};
use tempfile::tempdir;

struct ScriptedUafRuntime {
    steps: Mutex<Vec<AgentLoopStep>>,
}

impl ScriptedUafRuntime {
    fn new(steps: Vec<AgentLoopStep>) -> Self {
        Self {
            steps: Mutex::new(steps),
        }
    }
}

impl AgentRuntime for ScriptedUafRuntime {
    fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
        anyhow::bail!("not used by uaf-hunt tests")
    }

    fn supports_tools(&self) -> bool {
        true
    }

    fn next_step_blocking(
        &self,
        _request: &AgentToolLoopRequest,
        _history: &[LoopHistoryEntry],
    ) -> Result<AgentLoopStep> {
        let mut steps = self.steps.lock().unwrap();
        if steps.is_empty() {
            anyhow::bail!("scripted runtime exhausted")
        }
        Ok(steps.remove(0))
    }
}

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[test]
fn defaults_include_malloc_calloc_realloc_strdup_strndup() {
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("compile_commands.json"), "[]").unwrap();

    let input = json!({});
    let options = parse_uaf_hunt_input(&input, dir.path()).unwrap();

    let allocs: Vec<&str> = options
        .alloc_free_pairs
        .iter()
        .map(|pair| pair.alloc.as_str())
        .collect();
    assert!(allocs.contains(&"malloc"));
    assert!(allocs.contains(&"calloc"));
    assert!(allocs.contains(&"realloc"));
    assert!(allocs.contains(&"strdup"));
    assert!(allocs.contains(&"strndup"));
    let frees: Vec<&str> = options
        .alloc_free_pairs
        .iter()
        .map(|pair| pair.free.as_str())
        .collect();
    assert!(frees.iter().all(|free| *free == "free"));
}

#[test]
fn extra_alloc_free_pairs_extend_defaults_without_duplicating() {
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("compile_commands.json"), "[]").unwrap();

    let input = json!({
        "extraAllocFreePairs": [
            {"alloc": "zmalloc", "free": "zfree"},
            {"alloc": "sdsnewlen", "free": "sdsfree"},
            // Already in defaults — should not duplicate.
            {"alloc": "malloc", "free": "free"},
        ]
    });
    let options = parse_uaf_hunt_input(&input, dir.path()).unwrap();
    let zmalloc_count = options
        .alloc_free_pairs
        .iter()
        .filter(|pair| pair.alloc == "zmalloc")
        .count();
    let malloc_count = options
        .alloc_free_pairs
        .iter()
        .filter(|pair| pair.alloc == "malloc")
        .count();
    assert_eq!(zmalloc_count, 1);
    assert_eq!(malloc_count, 1, "default malloc pair was duplicated");
    assert!(options
        .alloc_free_pairs
        .iter()
        .any(|pair| pair.alloc == "sdsnewlen" && pair.free == "sdsfree"));
}

#[test]
fn alloc_free_pairs_replaces_defaults_entirely() {
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("compile_commands.json"), "[]").unwrap();

    let input = json!({
        "allocFreePairs": [
            {"alloc": "zmalloc", "free": "zfree"},
        ]
    });
    let options = parse_uaf_hunt_input(&input, dir.path()).unwrap();
    assert_eq!(options.alloc_free_pairs.len(), 1);
    assert_eq!(options.alloc_free_pairs[0].alloc, "zmalloc");
}

#[test]
fn empty_alloc_free_pairs_array_bails_with_helpful_message() {
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("compile_commands.json"), "[]").unwrap();

    let err = parse_uaf_hunt_input(&json!({"allocFreePairs": []}), dir.path()).unwrap_err();
    let message = format!("{err:#}");
    assert!(
        message.contains("allocFreePairs"),
        "missing field name in bail: {message}"
    );
    assert!(
        message.contains("defaults") || message.contains("default"),
        "no hint about removing the key to use defaults: {message}"
    );
}

#[test]
fn missing_compile_commands_json_bails_loudly() {
    let dir = tempdir().unwrap();
    let err = resolve_compile_commands_path(&json!({}), dir.path()).unwrap_err();
    let message = format!("{err:#}");
    assert!(
        message.contains("compile_commands.json"),
        "bail must name the missing file: {message}"
    );
    assert!(
        message.contains("bear") || message.contains("CMAKE_EXPORT_COMPILE_COMMANDS"),
        "bail must suggest a generator command: {message}"
    );
}

#[test]
fn compile_commands_found_under_build_subdir() {
    let dir = tempdir().unwrap();
    let build_dir = dir.path().join("build");
    std::fs::create_dir(&build_dir).unwrap();
    std::fs::write(build_dir.join("compile_commands.json"), "[]").unwrap();

    let resolved = resolve_compile_commands_path(&json!({}), dir.path()).unwrap();
    assert_eq!(resolved, build_dir.join("compile_commands.json"));
}

#[test]
fn explicit_compile_commands_path_honored() {
    let dir = tempdir().unwrap();
    let custom = dir.path().join("custom-cc.json");
    std::fs::write(&custom, "[]").unwrap();

    let resolved = resolve_compile_commands_path(
        &json!({"compileCommandsPath": custom.display().to_string()}),
        dir.path(),
    )
    .unwrap();
    assert_eq!(resolved, custom);
}

#[test]
fn default_max_agent_steps_is_120_with_a_400_cap() {
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("compile_commands.json"), "[]").unwrap();

    // No explicit override → use the new default.
    let default = parse_uaf_hunt_input(&json!({}), dir.path()).unwrap();
    assert_eq!(
        default.max_agent_steps, 120,
        "first live run hit the cap at 85 steps on a single alloc/free pair; \
         60 default was too low for any real codebase"
    );
    assert!(
        !default.include_non_production,
        "uaf-hunt should spend default budget on production code"
    );

    // Explicit override clamped at 400 (defense against runaway costs).
    let huge = parse_uaf_hunt_input(&json!({"maxAgentSteps": 10_000}), dir.path()).unwrap();
    assert_eq!(huge.max_agent_steps, 400);

    // Operator can pick anywhere in [4, 400].
    let custom = parse_uaf_hunt_input(&json!({"maxAgentSteps": 250}), dir.path()).unwrap();
    assert_eq!(custom.max_agent_steps, 250);

    let broad = parse_uaf_hunt_input(&json!({"includeNonProduction": true}), dir.path()).unwrap();
    assert!(broad.include_non_production);
}

#[test]
fn run_uaf_hunt_rejects_bare_model_before_clang_spawn() {
    let _guard = env_lock().lock().unwrap();
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("compile_commands.json"), "[]").unwrap();

    let previous = std::env::var_os("KUZUSHI_MCP_CLANG_BIN");
    std::env::set_var(
        "KUZUSHI_MCP_CLANG_BIN",
        dir.path().join("missing-kuzushi-mcp-clang"),
    );

    let runtime = ScriptedUafRuntime::new(vec![]);
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: None,
        findings_store: None,
        trace: None,
    };

    let err = run_uaf_hunt_report(
        &json!({"target": dir.path(), "model": "gpt-5.5"}),
        &ctx,
        Some(&runtime),
    )
    .unwrap_err();

    match previous {
        Some(value) => std::env::set_var("KUZUSHI_MCP_CLANG_BIN", value),
        None => std::env::remove_var("KUZUSHI_MCP_CLANG_BIN"),
    }

    let message = format!("{err:#}");
    assert!(
        message.contains("provider:model"),
        "bare model must fail shared model validation: {message}"
    );
    assert!(
        message.contains("uaf-hunt:hunt"),
        "error should name the tool policy boundary: {message}"
    );
    assert!(
        !message.contains("mcp-clang"),
        "model validation should happen before clang subprocess spawn: {message}"
    );
}

#[test]
fn method_not_found_for_callees_becomes_workaround_advisory() {
    let error = anyhow::anyhow!(
        "uaf-hunt: mcp-clang returned JSON-RPC error code -32601: method not found"
    );
    let advisory = rewrite_unsupported_method_error("clang.callees", &error)
        .expect("clangd's method-not-found error must produce an advisory");
    assert_eq!(advisory.method, "clang.callees");
    assert!(
        advisory.reason.contains("outgoingCalls"),
        "reason should name the specific LSP method: {}",
        advisory.reason
    );
    assert!(
        advisory.workaround.contains("clang_definition")
            && advisory.workaround.contains("read_file"),
        "workaround must name the fallback tools: {}",
        advisory.workaround
    );
    let json = advisory.to_tool_result();
    assert_eq!(json["unsupported"], json!(true));
    assert_eq!(json["method"], json!("clang.callees"));
}

#[test]
fn non_method_not_found_errors_pass_through_unchanged() {
    // E.g. the clang subprocess died with a stdout-closed error, or
    // clangd reported an invalid position. These should NOT become
    // advisories — they're real failures the operator needs to see.
    for chain in [
        "uaf-hunt: mcp-clang closed stdout unexpectedly",
        "uaf-hunt: tool clang.references returned error: position out of range",
        "ENOENT: compile_commands.json missing",
    ] {
        let advisory = rewrite_unsupported_method_error(
            "clang.references",
            &anyhow::anyhow!(chain.to_string()),
        );
        assert!(
            advisory.is_none(),
            "advisory should be None for non-method-not-found error: {chain}"
        );
    }
}

#[test]
#[cfg(unix)]
fn run_uaf_hunt_report_drives_tool_loop_and_repo_tools() {
    let _guard = env_lock().lock().unwrap();
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("compile_commands.json"), "[]").unwrap();
    std::fs::write(
        dir.path().join("src.c"),
        "void demo(char *arg) { malloc(4); query(arg); }\n",
    )
    .unwrap();

    let fake_clang = dir.path().join("kuzushi-mcp-clang");
    std::fs::write(
        &fake_clang,
        r#"#!/usr/bin/env bash
set -euo pipefail
while IFS= read -r line; do
  id="$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')"
  if printf '%s' "$line" | grep -q '"method":"shutdown"'; then
    exit 0
  elif printf '%s' "$line" | grep -q '"method":"initialize"'; then
    printf '{"jsonrpc":"2.0","id":%s,"result":{}}\n' "$id"
  else
    printf '{"jsonrpc":"2.0","id":%s,"result":{"isError":false,"structuredContent":{"definition":"src.c:1"}}}\n' "$id"
  fi
done
"#,
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&fake_clang).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&fake_clang, perms).unwrap();
    }

    let previous = std::env::var_os("KUZUSHI_MCP_CLANG_BIN");
    std::env::set_var("KUZUSHI_MCP_CLANG_BIN", &fake_clang);

    let runtime = ScriptedUafRuntime::new(vec![
        AgentLoopStep::ToolCall {
            call: ToolCall {
                name: "clang_definition".to_string(),
                input: json!({"file": "src.c", "line": 1, "column": 6}),
                call_id: "clang-1".to_string(),
            },
        },
        AgentLoopStep::ToolCall {
            call: ToolCall {
                name: "grep".to_string(),
                input: json!({"pattern": "malloc", "globs": ["*.c"], "maxResults": 5}),
                call_id: "grep-1".to_string(),
            },
        },
        AgentLoopStep::ToolCall {
            call: ToolCall {
                name: "read_file".to_string(),
                input: json!({"file": "src.c", "startLine": 1, "endLine": 1}),
                call_id: "read-1".to_string(),
            },
        },
        AgentLoopStep::ToolCall {
            call: ToolCall {
                name: "list_dir".to_string(),
                input: json!({"path": "."}),
                call_id: "list-1".to_string(),
            },
        },
        AgentLoopStep::Final {
            text: String::new(),
            structured: Some(json!({
                "findings": [{
                    "ruleId": "uaf-test",
                    "filePath": "src.c",
                    "startLine": 1,
                    "severity": "medium",
                    "message": "test finding"
                }]
            })),
            cost_usd: Some(0.03),
        },
    ]);
    let mut config = V2Config::default();
    config.model = Some("anthropic:claude-haiku-4-5".to_string());
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: None,
        findings_store: None,
        trace: None,
    };

    let report = run_uaf_hunt_report(&json!({"target": dir.path()}), &ctx, Some(&runtime)).unwrap();

    match previous {
        Some(value) => std::env::set_var("KUZUSHI_MCP_CLANG_BIN", value),
        None => std::env::remove_var("KUZUSHI_MCP_CLANG_BIN"),
    }

    assert_eq!(report.count, 1);
    assert_eq!(report.clang_tool_calls, 1);
    assert_eq!(report.steps_used, 5);
    assert_eq!(report.cost_usd, 0.03);
    assert!(report.first_clang_error.is_none());
}

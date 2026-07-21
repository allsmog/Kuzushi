//! Rust-executed tools for the harness-authoring agent loop.
//!
//! The model proposes actions; Rust performs them under hard containment:
//! `write_harness` only ever writes `<ws>/targets/c/<t>/harness.cpp`,
//! `update_build_spec` validates the build.json shape and allowlists the
//! compiler, and the build/smoke tools run through bounded subprocesses.
//! Reading the scanned repository goes through the shared read-only
//! code-nav toolbox, root-scoped to the source directory.

use super::super::{bootstrap, engine_cli, FuzzPaths};
use super::verdict::{smoke_result, tail_excerpt, SmokeResult};
use crate::runtime::{AgentTool, ToolBox, ToolCall, ToolResult};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const MAX_HARNESS_BYTES: usize = 256 * 1024;
const MAX_WORKORDER_BYTES: usize = 2 * 1024 * 1024;
const BUILD_ARGV0_ALLOWLIST: [&str; 7] =
    ["clang", "clang++", "gcc", "g++", "cc", "c++", "ar"];

#[derive(Clone)]
pub struct AuthorToolboxConfig {
    pub paths: FuzzPaths,
    pub target: String,
    pub build_timeout: Duration,
    pub smoke_seconds: u64,
}

pub fn author_tool_specs() -> Vec<AgentTool> {
    let mut specs = vec![
        read_workorder_tool(),
        write_harness_tool(),
        update_build_spec_tool(),
        build_target_tool(),
        run_harness_smoke_tool(),
    ];
    specs.extend(crate::code_nav::code_nav_tool_specs());
    specs
}

/// Code-nav tools read the scanned repo; the fuzz tools act only on this
/// target's directory inside the engine workspace.
pub fn author_toolbox(cfg: AuthorToolboxConfig) -> ToolBox {
    let mut toolbox = crate::code_nav::code_nav_toolbox(crate::code_nav::CodeNavConfig::new(
        cfg.paths.source_dir.clone(),
    ));
    let shared = Arc::new(cfg);
    register(&mut toolbox, &shared, "read_workorder", handle_read_workorder);
    register(&mut toolbox, &shared, "write_harness", handle_write_harness);
    register(&mut toolbox, &shared, "update_build_spec", handle_update_build_spec);
    register(&mut toolbox, &shared, "build_target", handle_build_target);
    register(&mut toolbox, &shared, "run_harness_smoke", handle_run_smoke);
    toolbox
}

fn register(
    toolbox: &mut ToolBox,
    cfg: &Arc<AuthorToolboxConfig>,
    name: &str,
    handler: fn(&AuthorToolboxConfig, &ToolCall) -> Result<Value>,
) {
    let cfg = Arc::clone(cfg);
    toolbox.register(name, move |call: &ToolCall| {
        Ok(match handler(&cfg, call) {
            Ok(output) => ToolResult {
                call_id: call.call_id.clone(),
                output,
                is_error: false,
            },
            Err(error) => ToolResult {
                call_id: call.call_id.clone(),
                output: json!({ "error": format!("{error:#}") }),
                is_error: true,
            },
        })
    });
}

fn handle_read_workorder(cfg: &AuthorToolboxConfig, _call: &ToolCall) -> Result<Value> {
    let path = bootstrap::target_workorder_path(&cfg.paths.workspace_root, &cfg.target);
    let body = crate::bounded_file::read_utf8_text(&path, MAX_WORKORDER_BYTES)
        .with_context(|| format!("no workorder at {}", path.display()))?;
    serde_json::from_str(&body).context("workorder.json is malformed JSON")
}

fn handle_write_harness(cfg: &AuthorToolboxConfig, call: &ToolCall) -> Result<Value> {
    let content = call
        .input
        .get("content")
        .and_then(Value::as_str)
        .context("write_harness needs a string `content` field")?;
    anyhow::ensure!(
        content.len() <= MAX_HARNESS_BYTES,
        "harness source is {} bytes; the cap is {MAX_HARNESS_BYTES}",
        content.len()
    );
    let path = harness_path(cfg);
    std::fs::create_dir_all(path.parent().context("harness path has no parent")?)?;
    std::fs::write(&path, content)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(json!({ "written": path.display().to_string(), "bytes": content.len() }))
}

fn handle_update_build_spec(cfg: &AuthorToolboxConfig, call: &ToolCall) -> Result<Value> {
    let spec = call
        .input
        .get("spec")
        .context("update_build_spec needs a `spec` object")?;
    validate_build_spec(spec)?;
    let path = build_spec_path(cfg);
    std::fs::create_dir_all(path.parent().context("build spec path has no parent")?)?;
    std::fs::write(&path, serde_json::to_vec_pretty(spec)?)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(json!({ "written": path.display().to_string() }))
}

fn handle_build_target(cfg: &AuthorToolboxConfig, _call: &ToolCall) -> Result<Value> {
    let invocation = engine_cli::engine_invocation(
        &cfg.paths,
        &[
            "target-build".to_string(),
            cfg.target.clone(),
            "--timeout-seconds".to_string(),
            cfg.build_timeout.as_secs().max(1).to_string(),
            "--workspace-root".to_string(),
            cfg.paths.workspace_root.display().to_string(),
        ],
    );
    let mut command = engine_cli::engine_command(&invocation);
    let output = crate::bounded_subprocess::output_with_control(
        &mut command,
        "afe target-build",
        None,
        cfg.build_timeout + Duration::from_secs(60),
    )?;
    let payload = engine_cli::parse_engine_json(&output.stdout).unwrap_or_else(|_| json!({}));
    Ok(json!({
        "built": fuzzer_binary(cfg).is_file(),
        "engine": payload,
        "stderr_tail": tail_excerpt(&String::from_utf8_lossy(&output.stderr), 4000),
    }))
}

fn handle_run_smoke(cfg: &AuthorToolboxConfig, _call: &ToolCall) -> Result<Value> {
    let result = run_smoke(cfg)?;
    Ok(json!({
        "exit_ok": result.exit_ok,
        "sanitizer_crash": result.crashed,
        "output_tail": result.excerpt,
    }))
}

/// One short libFuzzer run to prove the harness executes. Also called by
/// the orchestrator after the loop — the deterministic verdict never trusts
/// a smoke result the model merely claims.
pub fn run_smoke(cfg: &AuthorToolboxConfig) -> Result<SmokeResult> {
    let fuzzer = fuzzer_binary(cfg);
    anyhow::ensure!(fuzzer.is_file(), "no built fuzzer at {}", fuzzer.display());
    let mut command = std::process::Command::new(&fuzzer);
    command
        .arg("-runs=256")
        .arg(format!("-max_total_time={}", cfg.smoke_seconds.max(5)))
        .env("ASAN_OPTIONS", "detect_leaks=0:abort_on_error=0")
        // An unset DEBUGINFOD_URLS lets llvm-symbolizer hang on network
        // egress; force it empty.
        .env("DEBUGINFOD_URLS", "")
        .current_dir(&cfg.paths.workspace_root)
        .stdin(std::process::Stdio::null());
    let output = crate::bounded_subprocess::output_with_control(
        &mut command,
        "fuzz harness smoke",
        None,
        Duration::from_secs(cfg.smoke_seconds.max(5) + 60),
    )?;
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(smoke_result(output.status.success(), &combined))
}

pub fn fuzzer_binary(cfg: &AuthorToolboxConfig) -> PathBuf {
    cfg.paths
        .workspace_root
        .join("bin")
        .join(&cfg.target)
        .join("fuzzer")
}

fn harness_path(cfg: &AuthorToolboxConfig) -> PathBuf {
    bootstrap::target_dir(&cfg.paths.workspace_root, &cfg.target).join("harness.cpp")
}

fn build_spec_path(cfg: &AuthorToolboxConfig) -> PathBuf {
    bootstrap::target_dir(&cfg.paths.workspace_root, &cfg.target).join(".localfuzz/build.json")
}

/// The build spec is model-authored input that later becomes subprocess
/// argv: enforce the engine's `{notes?, steps: [{name, argv}]}` shape and
/// allowlist the command each step may launch.
pub fn validate_build_spec(spec: &Value) -> Result<()> {
    let object = spec.as_object().context("build spec must be a JSON object")?;
    for key in object.keys() {
        anyhow::ensure!(
            key == "steps" || key == "notes",
            "build spec key {key:?} is not allowed (only steps/notes)"
        );
    }
    let steps = object
        .get("steps")
        .and_then(Value::as_array)
        .context("build spec needs a non-empty `steps` array")?;
    anyhow::ensure!(!steps.is_empty(), "build spec needs at least one step");
    for step in steps {
        validate_build_step(step)?;
    }
    Ok(())
}

fn validate_build_step(step: &Value) -> Result<()> {
    let object = step.as_object().context("each build step must be an object")?;
    anyhow::ensure!(
        object.get("name").and_then(Value::as_str).is_some(),
        "each build step needs a string `name`"
    );
    let argv = object
        .get("argv")
        .and_then(Value::as_array)
        .context("each build step needs an `argv` array")?;
    let program = argv
        .first()
        .and_then(Value::as_str)
        .context("step argv must start with the compiler")?;
    anyhow::ensure!(
        argv.iter().all(|arg| arg.is_string()),
        "step argv entries must all be strings"
    );
    let basename = program.rsplit('/').next().unwrap_or(program);
    anyhow::ensure!(
        BUILD_ARGV0_ALLOWLIST.contains(&basename),
        "step command {program:?} is not an allowed compiler/archiver ({})",
        BUILD_ARGV0_ALLOWLIST.join(", ")
    );
    Ok(())
}

fn read_workorder_tool() -> AgentTool {
    AgentTool {
        name: "read_workorder".to_string(),
        description: "Read this target's authoring workorder: the sink rows to reach, source \
                      context, and why deterministic generation fell short."
            .to_string(),
        input_schema: json!({ "type": "object", "properties": {} }),
    }
}

fn write_harness_tool() -> AgentTool {
    AgentTool {
        name: "write_harness".to_string(),
        description: "Write the complete harness.cpp for this target (LLVMFuzzerTestOneInput \
                      convention). Overwrites the previous harness; always send the full file."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": { "content": { "type": "string" } },
            "required": ["content"]
        }),
    }
}

fn update_build_spec_tool() -> AgentTool {
    AgentTool {
        name: "update_build_spec".to_string(),
        description: "Replace the target's .localfuzz/build.json. Shape: {notes?: [string], \
                      steps: [{name: string, argv: [string]}]}; argv[0] must be a compiler or \
                      archiver (clang/clang++/gcc/g++/cc/c++/ar)."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": { "spec": { "type": "object" } },
            "required": ["spec"]
        }),
    }
}

fn build_target_tool() -> AgentTool {
    AgentTool {
        name: "build_target".to_string(),
        description: "Run the engine build for this target using the current harness and build \
                      spec. Returns whether bin/<target>/fuzzer exists plus compiler output."
            .to_string(),
        input_schema: json!({ "type": "object", "properties": {} }),
    }
}

fn run_harness_smoke_tool() -> AgentTool {
    AgentTool {
        name: "run_harness_smoke".to_string(),
        description: "Execute the built fuzzer briefly (bounded runs/time) to prove the harness \
                      works. Reports sanitizer crashes separately from setup failures."
            .to_string(),
        input_schema: json!({ "type": "object", "properties": {} }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_cfg(root: &std::path::Path) -> AuthorToolboxConfig {
        AuthorToolboxConfig {
            paths: FuzzPaths {
                afe_repo: root.join("afe"),
                python_bin: root.join("afe/.venv/bin/python"),
                workspace_root: root.join("ws"),
                data_root: root.join("ws/data"),
                source_dir: root.join("repo"),
            },
            target: "vhdx".to_string(),
            build_timeout: Duration::from_secs(60),
            smoke_seconds: 5,
        }
    }

    fn call(input: Value) -> ToolCall {
        ToolCall {
            name: "t".to_string(),
            input,
            call_id: "c1".to_string(),
        }
    }

    #[test]
    fn write_harness_lands_only_at_the_fixed_target_path_and_caps_size() {
        let temp = tempfile::tempdir().unwrap();
        let cfg = fixture_cfg(temp.path());

        let output = handle_write_harness(
            &cfg,
            &call(json!({"content": "// harness\nint LLVMFuzzerTestOneInput;"})),
        )
        .unwrap();

        let written = output["written"].as_str().unwrap();
        assert!(written.ends_with("ws/targets/c/vhdx/harness.cpp"), "{written}");
        assert!(std::path::Path::new(written).is_file());

        let oversized = "x".repeat(MAX_HARNESS_BYTES + 1);
        let error = handle_write_harness(&cfg, &call(json!({"content": oversized})))
            .unwrap_err()
            .to_string();
        assert!(error.contains("cap"), "{error}");
    }

    #[test]
    fn build_spec_validation_enforces_shape_and_compiler_allowlist() {
        let good = json!({
            "notes": ["authored"],
            "steps": [{"name": "libfuzzer", "argv": ["clang++", "-fsanitize=fuzzer,address", "harness.cpp"]}]
        });
        validate_build_spec(&good).unwrap();

        let bad_cases = [
            json!([]),
            json!({"steps": []}),
            json!({"steps": [{"name": "s", "argv": []}]}),
            json!({"steps": [{"name": "s", "argv": ["bash", "-c", "curl evil"]}]}),
            json!({"steps": [{"name": "s", "argv": ["/usr/bin/python3", "x"]}]}),
            json!({"steps": [{"argv": ["clang++"]}]}),
            json!({"steps": [{"name": "s", "argv": ["clang++", 7]}]}),
            json!({"steps": [{"name": "s", "argv": ["clang++"]}], "post": "rm -rf"}),
        ];
        for case in bad_cases {
            assert!(validate_build_spec(&case).is_err(), "{case}");
        }
        // A path-qualified allowed compiler passes.
        validate_build_spec(&json!({
            "steps": [{"name": "s", "argv": ["/usr/bin/clang++", "a.cpp"]}]
        }))
        .unwrap();
    }

    #[test]
    fn update_build_spec_rejects_invalid_and_writes_valid_specs() {
        let temp = tempfile::tempdir().unwrap();
        let cfg = fixture_cfg(temp.path());

        assert!(handle_update_build_spec(
            &cfg,
            &call(json!({"spec": {"steps": [{"name": "s", "argv": ["bash"]}]}}))
        )
        .is_err());

        handle_update_build_spec(
            &cfg,
            &call(json!({"spec": {"steps": [{"name": "s", "argv": ["clang++", "h.cpp"]}]}})),
        )
        .unwrap();
        assert!(bootstrap::target_dir(&cfg.paths.workspace_root, "vhdx")
            .join(".localfuzz/build.json")
            .is_file());
    }

    #[test]
    fn toolbox_surfaces_tool_errors_as_results_not_loop_failures() {
        let temp = tempfile::tempdir().unwrap();
        let mut toolbox = author_toolbox(fixture_cfg(temp.path()));
        let call = ToolCall {
            name: "read_workorder".to_string(),
            input: json!({}),
            call_id: "c9".to_string(),
        };

        let result = crate::runtime::ToolCallHandler::run(&mut toolbox, &call).unwrap();

        assert!(result.is_error);
        assert!(result.output["error"]
            .as_str()
            .unwrap()
            .contains("no workorder"));
    }

    #[test]
    fn author_tool_specs_include_fuzz_and_code_nav_tools() {
        let names: Vec<String> = author_tool_specs()
            .into_iter()
            .map(|tool| tool.name)
            .collect();
        for expected in [
            "read_workorder",
            "write_harness",
            "update_build_spec",
            "build_target",
            "run_harness_smoke",
            "read_source",
            "find_references",
        ] {
            assert!(names.contains(&expected.to_string()), "{expected}");
        }
    }
}

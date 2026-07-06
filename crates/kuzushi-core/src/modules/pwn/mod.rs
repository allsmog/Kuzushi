use super::registry::ToolDispatchResult;
use super::*;
use crate::runtime::{AgentQueryRequest, AgentRuntime, AgentStructuredOutput};
use anyhow::{Context, Result};
use kuzushi_mcp_common::cache::sha256_file_hex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const PWN_STATE_VERSION: u32 = 1;
const DEFAULT_REVNG_IMAGE: &str = "revng/revng:latest";
const PWN_AUTO_MAX_ACTIONS: usize = 6;
const PWN_AUTO_MAX_ROUNDS: usize = 3;

pub(in crate::modules) fn pwn_module() -> BuiltinModule {
    builtin_module(
        "pwn",
        "Pwn",
        ModuleKind::Offense,
        "Binary exploitation workflow support: profiling, reverse-engineering, exploit-state tracking, calibration, and candidate orchestration.",
        pwn_tools(),
        vec![],
    )
}

fn pwn_tools() -> Vec<ToolDescriptor> {
    vec![
        pwn_profile_binary_tool(),
        pwn_reverse_tool(),
        pwn_state_tool(),
        pwn_calibrate_local_tool(),
        pwn_run_candidates_tool(),
        pwn_auto_solve_tool(),
        pwn_menu_probe_tool(),
        pwn_exploit_run_tool(),
        pwn_heap_uaf_scan_tool(),
    ]
}

fn pwn_profile_binary_tool() -> ToolDescriptor {
    tool_with_options(
        "pwn:profile-binary",
        "Profile ELF/checksec/libc/loader/RPATH/architecture facts for a challenge binary.",
        vec![
            opt("binary", OptionType::Path, "Binary to profile.").required(),
            opt(
                "libc",
                OptionType::Path,
                "Optional libc paired with the challenge binary.",
            )
            .advanced(),
            opt(
                "ld",
                OptionType::Path,
                "Optional dynamic loader paired with the challenge binary.",
            )
            .advanced(),
        ],
    )
}

fn pwn_reverse_tool() -> ToolDescriptor {
    tool_with_options(
        "pwn:reverse",
        "Use rev.ng-backed reverse engineering plus host strings/symbol summaries to identify functions, loops, alloc/free sites, and dangerous IO.",
        vec![
            opt("binary", OptionType::Path, "Binary to reverse.").required(),
            opt("backend", OptionType::Enum, "Reverse-engineering backend.")
                .choices(&["revng"])
                .default(json!("revng")),
            opt("function", OptionType::String, "Optional function to decompile.").advanced(),
            opt(
                "revngImage",
                OptionType::String,
                "Container image used when native rev.ng is unavailable.",
            )
            .aliases(&["revng_image"])
            .default(json!(DEFAULT_REVNG_IMAGE))
            .advanced(),
            opt(
                "revngNative",
                OptionType::Path,
                "Explicit native rev.ng binary path.",
            )
            .aliases(&["revng_native"])
            .advanced(),
            opt(
                "revngContainerRuntime",
                OptionType::String,
                "Explicit container runtime for rev.ng (docker or podman).",
            )
            .aliases(&["revng_container_runtime"])
            .advanced(),
        ],
    )
}

fn pwn_state_tool() -> ToolDescriptor {
    tool_with_options(
        "pwn:state",
        "Read or update structured exploit state for a binary hash.",
        vec![
            opt(
                "binary",
                OptionType::Path,
                "Binary whose pwn state should be read or updated.",
            ),
            opt(
                "stateId",
                OptionType::String,
                "Existing state id or binary hash.",
            )
            .aliases(&["state_id"]),
            opt("action", OptionType::Enum, "State action.")
                .choices(&["read", "merge", "write", "record-failed"])
                .default(json!("read")),
            opt(
                "state",
                OptionType::Json,
                "Full replacement or merge patch state payload.",
            ),
            opt(
                "strategy",
                OptionType::String,
                "Failed strategy name for record-failed.",
            ),
            opt(
                "reason",
                OptionType::String,
                "Failure reason for record-failed.",
            ),
        ],
    )
}

fn pwn_calibrate_local_tool() -> ToolDescriptor {
    tool_with_options(
        "pwn:calibrate-local",
        "Run a local binary briefly and capture /proc/<pid>/maps plus script output for leak/base calibration.",
        vec![
            opt("binary", OptionType::Path, "Local binary to run.").required(),
            opt("argv", OptionType::StringList, "Additional argv values."),
            opt("env", OptionType::Json, "Environment object for the process."),
            opt("script", OptionType::String, "Bytes sent to stdin after spawn."),
        ],
    )
}

fn pwn_run_candidates_tool() -> ToolDescriptor {
    tool_with_options(
        "pwn:run-candidates",
        "Record and bound candidate exploit attempts against a local or remote target.",
        vec![
            opt(
                "target",
                OptionType::String,
                "Local command or remote endpoint label.",
            )
            .required(),
            opt(
                "stateId",
                OptionType::String,
                "State id returned by profile/state.",
            )
            .aliases(&["state_id"])
            .required(),
            opt(
                "maxAttempts",
                OptionType::Int,
                "Maximum candidate attempts to record.",
            )
            .aliases(&["max_attempts"])
            .default(json!(10)),
            opt(
                "parallelism",
                OptionType::Int,
                "Planned parallelism for remote-safe orchestration.",
            )
            .default(json!(1))
            .advanced(),
        ],
    )
}

fn pwn_auto_solve_tool() -> ToolDescriptor {
    tool_with_options(
        "pwn:auto-solve",
        "Use the configured LLM runtime to plan a pwn workflow for an arbitrary target.",
        vec![
            opt(
                "target",
                OptionType::Path,
                "Target binary, shared object, or challenge directory.",
            )
            .required(),
            model_option(),
        ],
    )
}

fn pwn_menu_probe_tool() -> ToolDescriptor {
    tool_with_options(
        "pwn:menu-probe",
        "Spawn a menu-driven challenge binary and probe each numbered choice to capture prompts, response shape, and refcount/UAF hints.",
        vec![
            opt("binary", OptionType::Path, "Binary or loader+binary path to probe.").required(),
            opt("argv", OptionType::StringList, "Additional argv values for the loader/binary."),
            opt("env", OptionType::Json, "Environment object for the process."),
            opt("maxChoices", OptionType::Int, "Upper bound on menu choices to probe.")
                .aliases(&["max_choices"])
                .default(json!(10)),
            opt("timeoutMs", OptionType::Int, "Per-probe wall-clock timeout in milliseconds.")
                .aliases(&["timeout_ms"])
                .default(json!(400)),
        ],
    )
}

fn pwn_exploit_run_tool() -> ToolDescriptor {
    tool_with_options(
        "pwn:exploit-run",
        "Execute a pwntools-style exploit script under a wall-clock timeout and capture stdout/stderr plus any LEAK/FLAG markers.",
        vec![
            opt("script", OptionType::Path, "Python exploit script to invoke.").required(),
            opt("python", OptionType::String, "Interpreter to invoke.")
                .default(json!("python3")),
            opt("argv", OptionType::StringList, "Additional argv passed to the script."),
            opt("env", OptionType::Json, "Environment object for the script invocation."),
            opt("workdir", OptionType::Path, "Working directory."),
            opt("timeoutMs", OptionType::Int, "Wall-clock timeout in milliseconds.")
                .aliases(&["timeout_ms"])
                .default(json!(15000)),
        ],
    )
}

fn pwn_heap_uaf_scan_tool() -> ToolDescriptor {
    tool_with_options(
        "pwn:heap-uaf-scan",
        "Scan a binary for refcount-based free patterns and other heap UAF indicators.",
        vec![opt("binary", OptionType::Path, "Binary to scan.").required()],
    )
}

pub(in crate::modules) fn dispatch_pwn_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> ToolDispatchResult {
    match name {
        "pwn:profile-binary" => Some(profile_binary(input, ctx)),
        "pwn:reverse" => Some(reverse_binary(input, ctx)),
        "pwn:state" => Some(state_tool(input, ctx)),
        "pwn:calibrate-local" => Some(calibrate_local(input, ctx)),
        "pwn:run-candidates" => Some(run_candidates(input, ctx)),
        "pwn:auto-solve" => Some(auto_solve(input, ctx, runtime)),
        "pwn:menu-probe" => Some(menu_probe(input, ctx)),
        "pwn:exploit-run" => Some(exploit_run(input, ctx)),
        "pwn:heap-uaf-scan" => Some(heap_uaf_scan(input, ctx)),
        _ => None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PwnState {
    version: u32,
    state_id: String,
    binary: BinaryMetadata,
    primitives: Vec<PrimitiveRecord>,
    leaks: Vec<Value>,
    candidate_bases: Vec<CandidateBase>,
    calibration: Vec<CalibrationRecord>,
    failed_strategies: Vec<StrategyAttempt>,
    artifacts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BinaryMetadata {
    path: String,
    hash: String,
    arch: Option<String>,
    libc: Option<String>,
    ld: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PrimitiveRecord {
    kind: String,
    confidence: f64,
    evidence: String,
    remote_safe: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CandidateBase {
    kind: String,
    value: String,
    confidence: f64,
    source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CalibrationRecord {
    timestamp: u64,
    pid: Option<u32>,
    argv: Vec<String>,
    maps_excerpt: Vec<String>,
    stdout_excerpt: String,
    stderr_excerpt: String,
    local_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StrategyAttempt {
    timestamp: u64,
    target: String,
    strategy: String,
    result: String,
    irreversible: bool,
}

fn profile_binary(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let binary = required_file(input, "binary")?;
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool-progress",
                "profile-binary",
                format!("profile {}", binary.display()),
            )
            .emit();
    }
    let libc = optional_file(input, "libc")?;
    let ld = optional_file(input, "ld")?;
    let hash = file_hash(&binary)?;
    let file_output = run_optional("file", &[binary.as_os_str()]);
    let readelf_header = run_optional("readelf", &[std::ffi::OsStr::new("-h"), binary.as_os_str()]);
    let readelf_dynamic =
        run_optional("readelf", &[std::ffi::OsStr::new("-d"), binary.as_os_str()]);
    let checksec = run_optional(
        "checksec",
        &[std::ffi::OsStr::new("--file"), binary.as_os_str()],
    );
    let arch = infer_arch(file_output.as_deref(), readelf_header.as_deref());
    let rpath = dynamic_entries(readelf_dynamic.as_deref(), &["RPATH", "RUNPATH"]);
    let needed = dynamic_entries(readelf_dynamic.as_deref(), &["NEEDED"]);
    let state_path = state_path_for(ctx, &hash)?;
    let state = load_or_new_state(
        &state_path,
        BinaryMetadata {
            path: binary.display().to_string(),
            hash: hash.clone(),
            arch: arch.clone(),
            libc: libc.as_ref().map(|path| path.display().to_string()),
            ld: ld.as_ref().map(|path| path.display().to_string()),
        },
    )?;
    save_state(&state_path, &state)?;
    Ok(json!({
        "stateId": hash,
        "statePath": state_path.display().to_string(),
        "binary": binary.display().to_string(),
        "hash": state.state_id,
        "arch": arch,
        "file": file_output,
        "readelfHeader": readelf_header,
        "checksec": checksec,
        "needed": needed,
        "rpath": rpath,
        "libc": libc.map(|path| path.display().to_string()),
        "ld": ld.map(|path| path.display().to_string()),
        "output": format!("pwn profile: {} ({})", binary.display(), state.binary.hash),
    }))
}

fn reverse_binary(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let request = ReverseBinaryRequest::from_input(input)?;
    emit_reverse_start(ctx, &request.binary, request.function.as_deref());
    let hash = file_hash(&request.binary)?;
    let strings = reverse_strings(&request.binary);
    let symbols = reverse_symbols(&request.binary);
    let dangerous_io = dangerous_io_hits(&strings, &symbols);
    let revng = run_revng(
        &request.binary,
        request.function.as_deref(),
        &request.revng_options,
    );
    update_reverse_state(ctx, &hash)?;
    Ok(reverse_binary_response(
        &request.binary,
        &hash,
        request.function.as_deref(),
        revng,
        strings,
        symbols,
        dangerous_io,
    ))
}

struct ReverseBinaryRequest {
    binary: PathBuf,
    function: Option<String>,
    revng_options: RevngOptions,
}

impl ReverseBinaryRequest {
    fn from_input(input: &Value) -> Result<Self> {
        Ok(Self {
            binary: required_file(input, "binary")?,
            function: input
                .get("function")
                .and_then(Value::as_str)
                .map(str::to_string),
            revng_options: RevngOptions::from_input(input)?,
        })
    }
}

fn emit_reverse_start(ctx: &ToolExecutionContext<'_>, binary: &Path, function: Option<&str>) {
    if let Some(trace) = ctx.trace {
        let label = function
            .map(|function| format!("revng decompile {function}"))
            .unwrap_or_else(|| format!("reverse {}", binary.display()));
        let _ = trace.step("tool-progress", "reverse", label).emit();
    }
}

fn reverse_strings(binary: &Path) -> String {
    run_optional("strings", &[binary.as_os_str()]).unwrap_or_default()
}

fn reverse_symbols(binary: &Path) -> String {
    run_optional("nm", &[std::ffi::OsStr::new("-an"), binary.as_os_str()])
        .or_else(|| {
            run_optional(
                "readelf",
                &[std::ffi::OsStr::new("-Ws"), binary.as_os_str()],
            )
        })
        .unwrap_or_default()
}

fn update_reverse_state(ctx: &ToolExecutionContext<'_>, hash: &str) -> Result<()> {
    let state_path = state_path_for(ctx, hash)?;
    if state_path.exists() {
        let mut state = read_state(&state_path)?;
        state.artifacts.push(format!("reverse:{}", now_unix()));
        save_state(&state_path, &state)?;
    }
    Ok(())
}

fn reverse_binary_response(
    binary: &Path,
    hash: &str,
    function: Option<&str>,
    revng: Value,
    strings: String,
    symbols: String,
    dangerous_io: Vec<String>,
) -> Value {
    json!({
        "binary": binary.display().to_string(),
        "stateId": hash,
        "function": function,
        "revng": revng,
        "functions": function_names(&symbols),
        "menuHints": menu_hints(&strings),
        "dangerousIo": dangerous_io,
        "allocatorHints": allocator_hints(&symbols),
        "strings": strings.lines().take(120).collect::<Vec<_>>(),
        "symbols": symbols.lines().take(160).collect::<Vec<_>>(),
    })
}

#[derive(Debug, Clone)]
struct RevngOptions {
    image: String,
    native: Option<PathBuf>,
    container_runtime: Option<String>,
}

impl RevngOptions {
    fn from_input(input: &Value) -> Result<Self> {
        Ok(Self {
            image: optional_string_input(input, &["revngImage", "revng_image"])?
                .unwrap_or_else(|| DEFAULT_REVNG_IMAGE.to_string()),
            native: optional_string_input(input, &["revngNative", "revng_native"])?
                .map(PathBuf::from),
            container_runtime: optional_string_input(
                input,
                &["revngContainerRuntime", "revng_container_runtime"],
            )?,
        })
    }
}

fn state_tool(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let (state_id, binary_meta) = state_identity(input)?;
    let path = state_path_for(ctx, &state_id)?;
    let action = input
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("read")
        .trim();
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step("tool-progress", "state", format!("state {action}"))
            .emit();
    }
    let mut state = load_or_new_state(&path, binary_meta)?;
    match action {
        "read" => {}
        "write" => {
            let payload = input
                .get("state")
                .context("pwn:state action=write requires state")?;
            state = serde_json::from_value(payload.clone()).context("invalid pwn state payload")?;
            save_state(&path, &state)?;
        }
        "merge" => {
            let payload = input
                .get("state")
                .context("pwn:state action=merge requires state")?;
            let mut current = serde_json::to_value(&state)?;
            merge_json(&mut current, payload.clone());
            state = serde_json::from_value(current).context("merged pwn state is invalid")?;
            save_state(&path, &state)?;
        }
        "record-failed" => {
            let strategy = input
                .get("strategy")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            let reason = input
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("unspecified")
                .to_string();
            state.failed_strategies.push(StrategyAttempt {
                timestamp: now_unix(),
                target: "state".to_string(),
                strategy,
                result: reason,
                irreversible: false,
            });
            save_state(&path, &state)?;
        }
        other => anyhow::bail!("unsupported pwn:state action {other:?}"),
    }
    Ok(json!({
        "stateId": state.state_id,
        "statePath": path.display().to_string(),
        "state": state,
    }))
}

fn calibrate_local(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let binary = required_file(input, "binary")?;
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool-progress",
                "calibrate-local",
                format!("calibrate {}", binary.display()),
            )
            .emit();
    }
    let hash = file_hash(&binary)?;
    let argv = input
        .get("argv")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut command = Command::new(&binary);
    if let Some(parent) = binary.parent() {
        command.current_dir(parent);
    }
    command
        .args(&argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(env) = input.get("env").and_then(Value::as_object) {
        for (key, value) in env {
            if let Some(value) = value.as_str() {
                command.env(key, value);
            }
        }
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("could not spawn {}", binary.display()))?;
    if let Some(script) = input.get("script").and_then(Value::as_str) {
        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(script.as_bytes()).ok();
        }
    }
    let pid = child.id();
    std::thread::sleep(Duration::from_millis(100));
    let maps_excerpt = fs::read_to_string(format!("/proc/{pid}/maps"))
        .map(|maps| {
            maps.lines()
                .take(80)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let output = wait_or_kill(child, Duration::from_millis(900))?;
    let record = CalibrationRecord {
        timestamp: now_unix(),
        pid: Some(pid),
        argv: argv.clone(),
        maps_excerpt,
        stdout_excerpt: String::from_utf8_lossy(&output.stdout)
            .chars()
            .take(1200)
            .collect(),
        stderr_excerpt: String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(1200)
            .collect(),
        local_only: true,
    };
    let state_path = state_path_for(ctx, &hash)?;
    let mut state = load_or_new_state(
        &state_path,
        BinaryMetadata {
            path: binary.display().to_string(),
            hash: hash.clone(),
            arch: None,
            libc: None,
            ld: None,
        },
    )?;
    state.calibration.push(record.clone());
    save_state(&state_path, &state)?;
    Ok(json!({
        "stateId": hash,
        "statePath": state_path.display().to_string(),
        "calibration": record,
    }))
}

fn run_candidates(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = input
        .get("target")
        .and_then(Value::as_str)
        .context("target is required")?
        .to_string();
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool-progress",
                "run-candidates",
                format!("candidate review {target}"),
            )
            .emit();
    }
    let state_id = input
        .get("stateId")
        .and_then(Value::as_str)
        .context("stateId is required")?;
    let max_attempts = input
        .get("maxAttempts")
        .and_then(Value::as_i64)
        .unwrap_or(10)
        .max(1) as usize;
    let parallelism = input
        .get("parallelism")
        .and_then(Value::as_i64)
        .unwrap_or(1)
        .max(1);
    let path = state_path_for(ctx, state_id)?;
    let mut state = read_state(&path)?;
    let irreversible = !Path::new(&target).exists();
    let attempts = state
        .candidate_bases
        .iter()
        .take(max_attempts)
        .map(|candidate| StrategyAttempt {
            timestamp: now_unix(),
            target: target.clone(),
            strategy: format!("try {} base {}", candidate.kind, candidate.value),
            result: "planned".to_string(),
            irreversible,
        })
        .collect::<Vec<_>>();
    state.failed_strategies.extend(attempts.clone());
    save_state(&path, &state)?;
    Ok(json!({
        "stateId": state_id,
        "statePath": path.display().to_string(),
        "target": target,
        "maxAttempts": max_attempts,
        "parallelism": parallelism,
        "irreversible": irreversible,
        "attempts": attempts,
        "output": "pwn candidate attempts recorded; execute irreversible remote operations only with explicit operator review",
    }))
}

fn menu_probe(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let config = MenuProbeConfig::from_input(input)?;
    emit_menu_probe_start(ctx, &config.binary);
    let initial = run_menu_probe_step(
        &config.binary,
        &config.argv,
        config.env,
        b"",
        config.timeout,
    )?;
    let prompts = extract_menu_prompts(&initial);
    let probes = collect_menu_probes(&config)?;
    Ok(menu_probe_output(&config.binary, &initial, prompts, probes))
}

struct MenuProbeConfig<'a> {
    binary: PathBuf,
    argv: Vec<String>,
    env: Option<&'a Value>,
    max_choices: u32,
    timeout: Duration,
}

impl<'a> MenuProbeConfig<'a> {
    fn from_input(input: &'a Value) -> Result<Self> {
        Ok(Self {
            binary: required_file(input, "binary")?,
            argv: string_list(input.get("argv")),
            env: input.get("env"),
            max_choices: menu_probe_max_choices(input),
            timeout: menu_probe_timeout(input),
        })
    }
}

fn menu_probe_max_choices(input: &Value) -> u32 {
    input
        .get("maxChoices")
        .and_then(Value::as_i64)
        .unwrap_or(10)
        .clamp(1, 32) as u32
}

fn menu_probe_timeout(input: &Value) -> Duration {
    Duration::from_millis(
        input
            .get("timeoutMs")
            .and_then(Value::as_i64)
            .unwrap_or(400)
            .clamp(50, 5_000) as u64,
    )
}

fn emit_menu_probe_start(ctx: &ToolExecutionContext<'_>, binary: &Path) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool-progress",
                "menu-probe",
                format!("probe {}", binary.display()),
            )
            .emit();
    }
}

fn collect_menu_probes(config: &MenuProbeConfig<'_>) -> Result<Vec<Value>> {
    let mut probes = Vec::new();
    for choice in 1..=config.max_choices {
        probes.push(menu_probe_choice(config, choice)?);
    }
    Ok(probes)
}

fn menu_probe_choice(config: &MenuProbeConfig<'_>, choice: u32) -> Result<Value> {
    let script = format!("{choice}\n\n\n\n");
    let observation = run_menu_probe_step(
        &config.binary,
        &config.argv,
        config.env,
        script.as_bytes(),
        config.timeout,
    )?;
    Ok(json!({
        "choice": choice,
        "stdoutExcerpt": observation.chars().take(800).collect::<String>(),
        "looksValid": menu_choice_looks_valid(&observation),
    }))
}

fn menu_choice_looks_valid(observation: &str) -> bool {
    !observation.contains("[-] Invalid choice") && !observation.contains("Invalid choice")
}

fn menu_probe_output(
    binary: &Path,
    initial: &str,
    prompts: Vec<String>,
    probes: Vec<Value>,
) -> Value {
    let prompt_count = prompts.len();
    let probe_count = probes.len();
    json!({
        "binary": binary.display().to_string(),
        "initialOutput": initial.chars().take(1600).collect::<String>(),
        "menuPrompts": prompts,
        "probes": probes,
        "output": format!(
            "menu probe finished -- {} prompts captured, {} choices probed",
            prompt_count,
            probe_count
        ),
    })
}

fn run_menu_probe_step(
    binary: &Path,
    argv: &[String],
    env_value: Option<&Value>,
    stdin_bytes: &[u8],
    timeout: Duration,
) -> Result<String> {
    let mut command = Command::new(binary);
    if let Some(parent) = binary.parent() {
        command.current_dir(parent);
    }
    command
        .args(argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(env) = env_value.and_then(Value::as_object) {
        for (key, value) in env {
            if let Some(value) = value.as_str() {
                command.env(key, value);
            }
        }
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("could not spawn {}", binary.display()))?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(stdin_bytes).ok();
        let _ = stdin.write_all(b"8\n");
    }
    let output = wait_or_kill(child, timeout)?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(text)
}

fn extract_menu_prompts(output: &str) -> Vec<String> {
    let mut prompts = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let starts_numeric =
            trimmed.chars().next().is_some_and(|c| c.is_ascii_digit()) && trimmed.contains('.');
        if starts_numeric && seen.insert(trimmed.to_string()) {
            prompts.push(trimmed.to_string());
        }
    }
    prompts
}

fn exploit_run(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let script = required_file(input, "script")?;
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool-progress",
                "exploit-run",
                format!("run exploit {}", script.display()),
            )
            .emit();
    }
    let python = input
        .get("python")
        .and_then(Value::as_str)
        .unwrap_or("python3")
        .to_string();
    let argv = string_list(input.get("argv"));
    let timeout = Duration::from_millis(
        input
            .get("timeoutMs")
            .and_then(Value::as_i64)
            .unwrap_or(15_000)
            .clamp(500, 600_000) as u64,
    );
    let mut command = Command::new(&python);
    let workdir = input
        .get("workdir")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .or_else(|| script.parent().map(Path::to_path_buf));
    if let Some(dir) = workdir.as_ref() {
        command.current_dir(dir);
    }
    command
        .arg(&script)
        .args(&argv)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(env) = input.get("env").and_then(Value::as_object) {
        for (key, value) in env {
            if let Some(value) = value.as_str() {
                command.env(key, value);
            }
        }
    }
    let child = command
        .spawn()
        .with_context(|| format!("could not spawn {} {}", python, script.display()))?;
    let output = wait_or_kill(child, timeout)?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let combined = format!("{stdout}\n{stderr}");
    let leaks = collect_leak_markers(&combined);
    let flag = extract_flag_marker(&combined);
    Ok(json!({
        "script": script.display().to_string(),
        "exitStatus": format!("{}", output.status),
        "stdoutExcerpt": stdout.chars().take(4000).collect::<String>(),
        "stderrExcerpt": stderr.chars().take(2000).collect::<String>(),
        "leaks": leaks,
        "flag": flag,
        "output": format!(
            "exploit-run completed status={} leaks={} flag={}",
            output.status,
            leaks.len(),
            flag.is_some()
        ),
    }))
}

fn collect_leak_markers(text: &str) -> Vec<Value> {
    let mut leaks = Vec::new();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("leak") || lower.contains("base =") || lower.contains("base=") {
            if let Some(hex_start) = line.find("0x") {
                let rest = &line[hex_start..];
                let hex_end = rest
                    .char_indices()
                    .skip(2)
                    .find(|(_, c)| !c.is_ascii_hexdigit())
                    .map(|(idx, _)| idx)
                    .unwrap_or(rest.len());
                let value = &rest[..hex_end];
                leaks.push(json!({
                    "line": line.trim(),
                    "value": value,
                }));
            }
        }
    }
    leaks
}

fn extract_flag_marker(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(idx) = line.find("HTB{") {
            let rest = &line[idx..];
            if let Some(end) = rest.find('}') {
                return Some(rest[..=end].to_string());
            }
        }
        if let Some(idx) = line.find("flag{") {
            let rest = &line[idx..];
            if let Some(end) = rest.find('}') {
                return Some(rest[..=end].to_string());
            }
        }
    }
    None
}

fn heap_uaf_scan(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let binary = required_file(input, "binary")?;
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool-progress",
                "heap-uaf-scan",
                format!("uaf scan {}", binary.display()),
            )
            .emit();
    }
    let mut disasm = Command::new("objdump");
    disasm
        .arg("-d")
        .arg("-M")
        .arg("intel")
        .arg(binary.as_os_str())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = disasm
        .output()
        .context("could not invoke objdump for heap UAF scan")?;
    if !output.status.success() {
        anyhow::bail!(
            "objdump exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let mut summary = HeapUafSummary::default();
    let lines: Vec<&str> = text.lines().collect();
    let mut window_after_free: Option<usize> = None;
    for (idx, line) in lines.iter().enumerate() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("call") && lower.contains("malloc@plt") {
            summary.malloc_call_sites += 1;
        }
        if lower.contains("call") && lower.contains("free@plt") {
            summary.free_call_sites += 1;
            window_after_free = Some(idx);
        }
        if lower.contains("lock") && (lower.contains("dec") || lower.contains("sub")) {
            summary.atomic_decrement_sites += 1;
        }
        if lower.contains("pthread_create@plt") || lower.contains("pthread_join@plt") {
            summary.uses_pthreads = true;
        }
        if lower.contains("pthread_mutex_lock@plt") {
            summary.uses_pthread_mutex = true;
        }
        if lower.contains("xchg") || (lower.contains("lock") && lower.contains("add")) {
            summary.atomic_increment_sites += 1;
        }
        if let Some(call_idx) = window_after_free {
            if idx - call_idx <= 8 && line.contains("mov") && line.contains("[r") {
                let last_token = line.split_whitespace().last().unwrap_or("");
                if last_token.contains("0") && !last_token.contains("rax") {
                    summary.post_free_clears += 1;
                    window_after_free = None;
                }
            }
            if idx - call_idx > 12 {
                window_after_free = None;
            }
        }
    }
    summary.likely_refcount_pattern =
        summary.atomic_decrement_sites > 0 && summary.free_call_sites > 0;
    summary.likely_uaf_pattern =
        summary.free_call_sites > 0 && summary.post_free_clears < summary.free_call_sites;
    summary.likely_threaded = summary.uses_pthreads;
    let exploitation_hints = suggest_uaf_hints(&summary);
    Ok(json!({
        "binary": binary.display().to_string(),
        "summary": summary,
        "exploitationHints": exploitation_hints,
        "output": format!(
            "heap UAF scan: refcount={} uaf={} threaded={}",
            summary.likely_refcount_pattern,
            summary.likely_uaf_pattern,
            summary.likely_threaded
        ),
    }))
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HeapUafSummary {
    malloc_call_sites: usize,
    free_call_sites: usize,
    atomic_decrement_sites: usize,
    atomic_increment_sites: usize,
    post_free_clears: usize,
    uses_pthreads: bool,
    uses_pthread_mutex: bool,
    likely_refcount_pattern: bool,
    likely_uaf_pattern: bool,
    likely_threaded: bool,
}

fn suggest_uaf_hints(summary: &HeapUafSummary) -> Vec<String> {
    let mut hints = Vec::new();
    if summary.likely_refcount_pattern && summary.likely_uaf_pattern {
        hints.push(
            "Refcount-based free without pointer/alive clear is the canonical UAF pattern -- delete leaves slot reusable for View/Edit primitives.".to_string(),
        );
    }
    if summary.likely_threaded {
        hints.push(
            "Threaded program: race conditions between worker and main may amplify the UAF (e.g. queued Process op double-frees once refcount reaches 0)."
                .to_string(),
        );
    }
    if summary.malloc_call_sites > 0 && summary.free_call_sites > 0 {
        hints.push(
            "Standard tcache poisoning workflow: free two chunks of the same size, leak fd via UAF view, edit fd to redirect malloc to a controlled address."
                .to_string(),
        );
    }
    if summary.atomic_decrement_sites > 1 {
        hints.push(
            "Multiple atomic decrements suggest refcount manipulation -- consider triggering Process+Delete races for double-free or extra refcount drops."
                .to_string(),
        );
    }
    hints
}

fn string_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn auto_solve(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let target = required_existing_path(input, "target")?;
    let binary = generic_binary_target(&target)
        .with_context(|| format!("could not find an ELF target under {}", target.display()))?;
    let runtime =
        runtime.with_context(|| crate::runtime::missing_agent_runtime_message("pwn:auto-solve"))?;
    let model = resolve_tool_model("pwn:auto-solve", input, ctx)?;
    let profile = profile_binary(&json!({ "binary": binary }), ctx)?;
    let reverse_summary = generic_reverse_summary(&binary);
    let loop_report = run_pwn_observe_replan_loop(
        runtime,
        &model,
        &target,
        &binary,
        &profile,
        &reverse_summary,
        ctx,
    )?;
    let mut output = auto_solve_generic(&target, &binary, profile, reverse_summary)?;
    attach_auto_solve_loop_report(&mut output, &model, &loop_report);
    Ok(output)
}

fn attach_auto_solve_loop_report(output: &mut Value, model: &str, loop_report: &Value) {
    let Value::Object(object) = output else {
        return;
    };
    object.insert(
        "llmPlanner".to_string(),
        json!({
            "used": true,
            "model": model,
            "reason": "configured LLM observe/replan loop",
            "decision": loop_report.get("finalDecision").cloned(),
            "iterations": loop_report.get("iterations").cloned(),
        }),
    );
    object.insert(
        "actionExecution".to_string(),
        loop_report
            .get("actionExecution")
            .cloned()
            .unwrap_or_else(|| json!({"executed": false, "results": []})),
    );
    object.insert("actionsExecuted".to_string(), json!(true));
}

fn run_pwn_observe_replan_loop(
    runtime: &dyn AgentRuntime,
    model: &str,
    target: &Path,
    binary: &Path,
    profile: &Value,
    reverse_summary: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let mut observations = Vec::new();
    let mut iterations = Vec::new();
    let mut all_results = Vec::new();
    let mut final_decision = Value::Null;

    for round in 0..PWN_AUTO_MAX_ROUNDS {
        if let Some(trace) = ctx.trace {
            let _ = trace
                .step("reasoning", "auto-solve", format!("planner round {round}"))
                .emit();
        }
        let decision = query_pwn_strategy_planner(
            runtime,
            model,
            target,
            profile,
            reverse_summary,
            &observations,
            round,
        )?;
        validate_pwn_strategy_decision(&decision)?;
        let planner_report = planner_report(
            true,
            Some(model.to_string()),
            "configured LLM observe/replan loop",
            Some(decision.clone()),
        );
        let action_results =
            execute_pwn_llm_actions(ctx, binary, &planner_report, profile, reverse_summary)?;
        let round_results = action_results
            .get("results")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let stopped = round_results.iter().any(is_stop_result);
        observations.push(compact_json_strings(
            &json!({
                "round": round,
                "decision": compact_decision_for_observation(&decision),
                "actionExecution": action_results,
            }),
            1800,
        ));
        all_results.extend(round_results);
        iterations.push(json!({
            "round": round,
            "decision": decision,
            "actionExecution": observations.last().and_then(|obs| obs.get("actionExecution")).cloned(),
        }));
        final_decision = planner_report
            .get("decision")
            .cloned()
            .unwrap_or(Value::Null);
        if stopped || !has_followup_action(iterations.last()) {
            break;
        }
    }

    Ok(json!({
        "finalDecision": final_decision,
        "iterations": iterations,
        "observations": observations,
        "actionExecution": {
            "executed": !all_results.is_empty(),
            "maxRounds": PWN_AUTO_MAX_ROUNDS,
            "maxActionsPerRound": PWN_AUTO_MAX_ACTIONS,
            "results": all_results,
        }
    }))
}

#[cfg(test)]
fn plan_auto_solve_strategy(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    target: &Path,
    profile: &Value,
    reverse_summary: &Value,
) -> Result<Value> {
    let runtime =
        runtime.with_context(|| crate::runtime::missing_agent_runtime_message("pwn:auto-solve"))?;
    let model = resolve_tool_model("pwn:auto-solve", input, ctx)?;
    let observations = Vec::new();
    let decision = query_pwn_strategy_planner(
        runtime,
        &model,
        target,
        profile,
        reverse_summary,
        &observations,
        0,
    )?;
    validate_pwn_strategy_decision(&decision)?;
    Ok(planner_report(
        true,
        Some(model),
        "configured LLM planner",
        Some(decision),
    ))
}

fn validate_pwn_strategy_decision(decision: &Value) -> Result<()> {
    let strategy = decision
        .get("strategy")
        .and_then(Value::as_str)
        .context("pwn:auto-solve LLM planner response omitted strategy")?;
    match strategy {
        "generic-analysis" => Ok(()),
        "unsupported" => {
            anyhow::bail!("pwn:auto-solve LLM planner could not produce a generic plan")
        }
        other => {
            anyhow::bail!("pwn:auto-solve LLM planner selected unsupported strategy {other:?}")
        }
    }
}

fn planner_report(
    used: bool,
    model: Option<String>,
    reason: &str,
    decision: Option<Value>,
) -> Value {
    json!({
        "used": used,
        "model": model,
        "reason": reason,
        "decision": decision,
    })
}

fn query_pwn_strategy_planner(
    runtime: &dyn AgentRuntime,
    model: &str,
    target: &Path,
    profile: &Value,
    reverse_summary: &Value,
    observations: &[Value],
    round: usize,
) -> Result<Value> {
    let facts = target_facts(target);
    let schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["strategy", "reason", "confidence", "actions"],
        "properties": {
            "strategy": {
                "type": "string",
                "enum": ["generic-analysis", "unsupported"]
            },
            "reason": { "type": "string" },
            "exploitPath": {
                "type": "string",
                "enum": ["unknown", "stack-overflow", "format-string", "heap-uaf", "heap-overflow", "integer-bug", "command-injection", "file-read", "rop-ret2libc"]
            },
            "nextActions": {
                "type": "array",
                "items": { "type": "string" },
                "maxItems": 8
            },
            "actions": {
                "type": "array",
                "maxItems": PWN_AUTO_MAX_ACTIONS,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["operation", "reason"],
                    "properties": {
                        "operation": {
                            "type": "string",
                            "enum": ["reverse-function", "calibrate-local", "record-primitive", "stop"]
                        },
                        "reason": { "type": "string" },
                        "function": { "type": "string" },
                        "primitive": {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["kind", "confidence", "evidence", "remoteSafe"],
                            "properties": {
                                "kind": {
                                    "type": "string",
                                    "enum": [
                                        "leak",
                                        "arbitrary-read",
                                        "arbitrary-write",
                                        "heap-overlap",
                                        "tcache-poison",
                                        "stack-leak",
                                        "control-flow-target"
                                    ]
                                },
                                "confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                                "evidence": { "type": "string" },
                                "remoteSafe": { "type": "boolean" }
                            }
                        }
                    }
                }
            },
            "confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 }
        }
    });
    let prompt = format!(
        "Build a generic pwn workflow plan for these target facts.\n\
         Use generic-analysis when the target should be profiled/reversed/calibrated. \
         Use unsupported only when it is not a pwnable binary or challenge artifact.\n\
         Return local, non-remote actions only. Allowed operations are: \
         reverse-function for deeper static inspection, calibrate-local for executable local binaries, \
         record-primitive for evidence-backed exploit facts, and stop when no safe action is justified. \
         Do not request shell commands, remote attempts, brute force, or exploit payload execution. \
         This is round {round}; if prior observations are sufficient, return a stop action and explain the next operator-safe work.\n\
         Do not repeat an action already present in prior observations unless the prior observation failed and a different function is needed.\n\
         Target facts:\n{}\n\nProfile:\n{}\n\nReverse summary:\n{}\n\nPrior observations:\n{}",
        serde_json::to_string_pretty(&facts)?,
        serde_json::to_string_pretty(profile)?,
        serde_json::to_string_pretty(reverse_summary)?,
        serde_json::to_string_pretty(observations)?
    );
    let request = AgentQueryRequest::new(
        model,
        std::env::current_dir().context("resolve current directory for pwn planner")?,
        "You are Kuzushi's binary exploitation strategy planner. Return strict JSON. Do not generate exploit code or shell commands.",
        prompt,
    )
    .with_structured_output(AgentStructuredOutput::json_schema("pwn_auto_solve_plan", schema))
    .with_max_output_tokens(600)
    .with_temperature(0.0);
    let response = runtime.query_blocking(request)?;
    if let Some(structured) = response.structured {
        return Ok(structured);
    }
    serde_json::from_str(&response.text)
        .context("pwn:auto-solve LLM planner returned non-JSON text")
}

fn compact_decision_for_observation(decision: &Value) -> Value {
    json!({
        "strategy": decision.get("strategy").cloned(),
        "reason": decision.get("reason").cloned(),
        "exploitPath": decision.get("exploitPath").cloned(),
        "actions": decision.get("actions").cloned(),
        "confidence": decision.get("confidence").cloned(),
    })
}

fn is_stop_result(result: &Value) -> bool {
    result
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|status| status == "stopped")
}

fn has_followup_action(iteration: Option<&Value>) -> bool {
    iteration
        .and_then(|item| item.get("actionExecution"))
        .and_then(|execution| execution.get("results"))
        .and_then(Value::as_array)
        .is_some_and(|results| {
            results.iter().any(|result| {
                result
                    .get("status")
                    .and_then(Value::as_str)
                    .is_some_and(|status| matches!(status, "ok" | "partial"))
            })
        })
}

fn compact_json_strings(value: &Value, max_chars: usize) -> Value {
    match value {
        Value::String(text) => {
            let mut compact = text.chars().take(max_chars).collect::<String>();
            if text.chars().count() > max_chars {
                compact.push_str("...");
            }
            Value::String(compact)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| compact_json_strings(item, max_chars))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.clone(), compact_json_strings(item, max_chars)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn execute_pwn_llm_actions(
    ctx: &ToolExecutionContext<'_>,
    binary: &Path,
    planner_report: &Value,
    profile: &Value,
    reverse_summary: &Value,
) -> Result<Value> {
    let actions = planner_report
        .get("decision")
        .and_then(|decision| decision.get("actions"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut results = Vec::new();
    for (index, action) in actions.into_iter().take(PWN_AUTO_MAX_ACTIONS).enumerate() {
        let operation = action
            .get("operation")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let reason = action
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("no reason provided");
        let result = match operation {
            "reverse-function" => {
                execute_reverse_function_action(index, reason, &action, binary, ctx)
            }
            "calibrate-local" => execute_calibrate_local_action(index, reason, binary, ctx),
            "record-primitive" => execute_record_primitive_action(
                index,
                reason,
                &action,
                profile,
                reverse_summary,
                ctx,
            ),
            "stop" => Ok(json!({
                "index": index,
                "operation": operation,
                "reason": reason,
                "status": "stopped",
            })),
            other => Ok(json!({
                "index": index,
                "operation": other,
                "reason": reason,
                "status": "rejected",
                "message": "operation is not in the pwn:auto-solve allowlist",
            })),
        }?;
        let should_stop = result
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|status| status == "stopped");
        results.push(result);
        if should_stop {
            break;
        }
    }
    Ok(json!({
        "executed": !results.is_empty(),
        "maxActions": PWN_AUTO_MAX_ACTIONS,
        "results": results,
    }))
}

fn execute_reverse_function_action(
    index: usize,
    reason: &str,
    action: &Value,
    binary: &Path,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let function = action
        .get("function")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty());
    let mut input = json!({ "binary": binary });
    if let Some(function) = function {
        input["function"] = json!(function);
    }
    let reverse = reverse_binary(&input, ctx)?;
    let status = if revng_observation_failed(&reverse) {
        "partial"
    } else {
        "ok"
    };
    Ok(json!({
        "index": index,
        "operation": "reverse-function",
        "reason": reason,
        "status": status,
        "function": function,
        "observation": summarize_reverse_observation(&reverse),
    }))
}

fn execute_calibrate_local_action(
    index: usize,
    reason: &str,
    binary: &Path,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    if !is_local_executable(binary) {
        return Ok(json!({
            "index": index,
            "operation": "calibrate-local",
            "reason": reason,
            "status": "skipped",
            "message": "target binary is not marked executable",
        }));
    }
    let calibration = calibrate_local(&json!({ "binary": binary }), ctx)?;
    Ok(json!({
        "index": index,
        "operation": "calibrate-local",
        "reason": reason,
        "status": "ok",
        "observation": {
            "pid": calibration.pointer("/calibration/pid").cloned(),
            "mapsExcerpt": calibration.pointer("/calibration/mapsExcerpt").cloned(),
            "stdoutExcerpt": calibration.pointer("/calibration/stdoutExcerpt").cloned(),
            "stderrExcerpt": calibration.pointer("/calibration/stderrExcerpt").cloned(),
            "statePath": calibration.get("statePath").cloned(),
        },
    }))
}

fn execute_record_primitive_action(
    index: usize,
    reason: &str,
    action: &Value,
    profile: &Value,
    reverse_summary: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let Some(primitive) = action.get("primitive") else {
        return Ok(json!({
            "index": index,
            "operation": "record-primitive",
            "reason": reason,
            "status": "skipped",
            "message": "planner did not include a primitive record",
        }));
    };
    let record = primitive_record_from_action(primitive, reverse_summary)?;
    let path = state_path_from_profile(profile, ctx)?;
    let mut state = read_state(&path)?;
    let already_recorded = state
        .primitives
        .iter()
        .any(|existing| existing.kind == record.kind && existing.evidence == record.evidence);
    if !already_recorded {
        state.primitives.push(record.clone());
        save_state(&path, &state)?;
    }
    Ok(json!({
        "index": index,
        "operation": "record-primitive",
        "reason": reason,
        "status": "ok",
        "recorded": !already_recorded,
        "primitive": record,
        "statePath": path.display().to_string(),
    }))
}

fn primitive_record_from_action(
    primitive: &Value,
    reverse_summary: &Value,
) -> Result<PrimitiveRecord> {
    let kind = primitive
        .get("kind")
        .and_then(Value::as_str)
        .context("primitive.kind is required")?
        .to_string();
    let evidence = primitive
        .get("evidence")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| summarize_reverse_summary_for_evidence(reverse_summary));
    let confidence = primitive
        .get("confidence")
        .and_then(Value::as_f64)
        .unwrap_or(0.5)
        .clamp(0.0, 1.0);
    let remote_safe = primitive
        .get("remoteSafe")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(PrimitiveRecord {
        kind,
        confidence,
        evidence,
        remote_safe,
    })
}

fn state_path_from_profile(profile: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    if let Some(path) = profile.get("statePath").and_then(Value::as_str) {
        return Ok(PathBuf::from(path));
    }
    let state_id = profile
        .get("stateId")
        .and_then(Value::as_str)
        .context("profile omitted stateId/statePath")?;
    state_path_for(ctx, state_id)
}

fn summarize_reverse_observation(reverse: &Value) -> Value {
    json!({
        "function": reverse.get("function").cloned(),
        "revng": reverse.get("revng").map(summarize_revng_observation),
        "functions": take_json_array(reverse.get("functions"), 24),
        "menuHints": take_json_array(reverse.get("menuHints"), 16),
        "dangerousIo": take_json_array(reverse.get("dangerousIo"), 16),
        "allocatorHints": take_json_array(reverse.get("allocatorHints"), 16),
    })
}

fn summarize_revng_observation(revng: &Value) -> Value {
    json!({
        "ok": revng.get("ok").cloned(),
        "errorExcerpt": revng
            .get("error")
            .and_then(Value::as_str)
            .map(|error| error.chars().take(1200).collect::<String>()),
        "next": revng.get("next").cloned(),
        "outputExcerpt": revng
            .get("output")
            .and_then(Value::as_str)
            .map(|output| output.chars().take(1200).collect::<String>()),
    })
}

fn revng_observation_failed(reverse: &Value) -> bool {
    reverse
        .get("revng")
        .and_then(|revng| revng.get("ok"))
        .and_then(Value::as_bool)
        .is_some_and(|ok| !ok)
}

fn take_json_array(value: Option<&Value>, limit: usize) -> Value {
    value
        .and_then(Value::as_array)
        .map(|items| items.iter().take(limit).cloned().collect::<Vec<_>>())
        .map(Value::Array)
        .unwrap_or_else(|| json!([]))
}

fn summarize_reverse_summary_for_evidence(reverse_summary: &Value) -> String {
    serde_json::to_string(&json!({
        "dangerousIo": take_json_array(reverse_summary.get("dangerousIo"), 8),
        "menuHints": take_json_array(reverse_summary.get("menuHints"), 8),
        "allocatorHints": take_json_array(reverse_summary.get("allocatorHints"), 8),
    }))
    .unwrap_or_else(|_| "reverse summary unavailable".to_string())
}

fn is_local_executable(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn target_facts(target: &Path) -> Value {
    let entries = if target.is_dir() {
        list_dir_names(target, 32)
    } else {
        Vec::new()
    };
    let parent_entries = target
        .parent()
        .filter(|parent| parent.is_dir())
        .map(|parent| list_dir_names(parent, 32))
        .unwrap_or_default();
    json!({
        "path": target.display().to_string(),
        "fileName": target.file_name().map(|name| name.to_string_lossy().to_string()),
        "isFile": target.is_file(),
        "isDirectory": target.is_dir(),
        "directoryEntries": entries,
        "parentEntries": parent_entries,
    })
}

fn list_dir_names(dir: &Path, limit: usize) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .take(limit)
        .collect()
}

fn auto_solve_generic(
    target: &Path,
    binary: &Path,
    profile: Value,
    reverse_summary: Value,
) -> Result<Value> {
    let state_id = profile
        .get("stateId")
        .and_then(Value::as_str)
        .map(str::to_string);
    let state_path = profile
        .get("statePath")
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(json!({
        "strategy": "generic-analysis",
        "executed": false,
        "irreversible": false,
        "autoExploit": false,
        "target": target.display().to_string(),
        "binary": binary.display().to_string(),
        "stateId": state_id,
        "statePath": state_path,
        "profile": profile,
        "reverseSummary": reverse_summary,
        "output": "LLM pwn workflow plan recorded; exploit execution requires explicit candidate state",
    }))
}

fn generic_binary_target(target: &Path) -> Option<PathBuf> {
    if target.is_file() {
        return Some(target.to_path_buf());
    }
    let entries = fs::read_dir(target).ok()?;
    entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .find(|path| path.is_file() && is_probable_elf(path))
}

fn is_probable_elf(path: &Path) -> bool {
    let Ok(bytes) = fs::read(path) else {
        return false;
    };
    bytes.starts_with(b"\x7fELF")
}

fn generic_reverse_summary(binary: &Path) -> Value {
    let strings = run_optional("strings", &[binary.as_os_str()]).unwrap_or_default();
    let symbols = run_optional("nm", &[std::ffi::OsStr::new("-an"), binary.as_os_str()])
        .or_else(|| {
            run_optional(
                "readelf",
                &[std::ffi::OsStr::new("-Ws"), binary.as_os_str()],
            )
        })
        .unwrap_or_default();
    json!({
        "dangerousIo": dangerous_io_hits(&strings, &symbols),
        "menuHints": menu_hints(&strings),
        "allocatorHints": allocator_hints(&symbols),
        "functions": function_names(&symbols),
        "strings": strings.lines().take(80).collect::<Vec<_>>(),
    })
}

fn state_identity(input: &Value) -> Result<(String, BinaryMetadata)> {
    if let Some(binary) = input.get("binary").and_then(Value::as_str) {
        let binary = canonical_file(binary)?;
        let hash = file_hash(&binary)?;
        return Ok((
            hash.clone(),
            BinaryMetadata {
                path: binary.display().to_string(),
                hash,
                arch: None,
                libc: None,
                ld: None,
            },
        ));
    }
    let state_id = input
        .get("stateId")
        .and_then(Value::as_str)
        .context("pwn:state requires binary or stateId")?
        .to_string();
    Ok((
        state_id.clone(),
        BinaryMetadata {
            path: String::new(),
            hash: state_id,
            arch: None,
            libc: None,
            ld: None,
        },
    ))
}

fn load_or_new_state(path: &Path, binary: BinaryMetadata) -> Result<PwnState> {
    if path.exists() {
        return read_state(path);
    }
    Ok(PwnState {
        version: PWN_STATE_VERSION,
        state_id: binary.hash.clone(),
        binary,
        primitives: Vec::new(),
        leaks: Vec::new(),
        candidate_bases: Vec::new(),
        calibration: Vec::new(),
        failed_strategies: Vec::new(),
        artifacts: Vec::new(),
    })
}

fn read_state(path: &Path) -> Result<PwnState> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("could not read {}", path.display()))?;
    let mut value: Value = serde_json::from_str(&raw).context("invalid pwn state JSON")?;
    migrate_state_value(&mut value);
    serde_json::from_value(value).context("invalid pwn state schema")
}

fn save_state(path: &Path, state: &PwnState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(state)?)
        .with_context(|| format!("could not write {}", path.display()))
}

fn migrate_state_value(value: &mut Value) {
    if value.get("version").is_none() {
        value["version"] = json!(PWN_STATE_VERSION);
    }
    for key in [
        "primitives",
        "leaks",
        "candidateBases",
        "calibration",
        "failedStrategies",
        "artifacts",
    ] {
        if value.get(key).is_none() {
            value[key] = json!([]);
        }
    }
}

fn state_path_for(ctx: &ToolExecutionContext<'_>, state_id: &str) -> Result<PathBuf> {
    let root = ctx
        .workspace
        .map(|workspace| workspace.root().to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    Ok(root
        .join(".kuzushi")
        .join("pwn")
        .join(state_id)
        .join("state.json"))
}

fn required_file(input: &Value, name: &str) -> Result<PathBuf> {
    let raw = input
        .get(name)
        .and_then(Value::as_str)
        .with_context(|| format!("{name} is required"))?;
    canonical_file(raw)
}

fn optional_file(input: &Value, name: &str) -> Result<Option<PathBuf>> {
    input
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(canonical_file)
        .transpose()
}

fn required_existing_path(input: &Value, name: &str) -> Result<PathBuf> {
    let raw = input
        .get(name)
        .and_then(Value::as_str)
        .with_context(|| format!("{name} is required"))?;
    let path = PathBuf::from(raw);
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    fs::canonicalize(&path).with_context(|| format!("{name} does not exist: {}", path.display()))
}

fn canonical_file(raw: &str) -> Result<PathBuf> {
    let path = PathBuf::from(raw);
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    let canonical = fs::canonicalize(&path)
        .with_context(|| format!("file does not exist: {}", path.display()))?;
    if !canonical.is_file() {
        anyhow::bail!("path is not a file: {}", canonical.display());
    }
    Ok(canonical)
}

fn file_hash(path: &Path) -> Result<String> {
    sha256_file_hex(path).with_context(|| format!("could not hash {}", path.display()))
}

fn run_optional(binary: &str, args: &[&std::ffi::OsStr]) -> Option<String> {
    let output = Command::new(binary)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn dynamic_entries(output: Option<&str>, names: &[&str]) -> Vec<String> {
    output
        .into_iter()
        .flat_map(str::lines)
        .filter(|line| names.iter().any(|name| line.contains(name)))
        .map(|line| line.trim().to_string())
        .collect()
}

fn infer_arch(file_output: Option<&str>, readelf_header: Option<&str>) -> Option<String> {
    file_output
        .and_then(|line| {
            line.split(',').find(|part| {
                part.contains("x86-64") || part.contains("ARM") || part.contains("MIPS")
            })
        })
        .map(|part| part.trim().to_string())
        .or_else(|| {
            readelf_header?
                .lines()
                .find(|line| line.trim_start().starts_with("Machine:"))
                .map(|line| line.trim().to_string())
        })
}

fn dangerous_io_hits(strings: &str, symbols: &str) -> Vec<String> {
    let haystack = format!("{strings}\n{symbols}");
    [
        "gets", "scanf", "strcpy", "strcat", "sprintf", "read", "recv", "system", "malloc", "free",
    ]
    .iter()
    .filter(|needle| haystack.contains(**needle))
    .map(|needle| (*needle).to_string())
    .collect()
}

fn function_names(symbols: &str) -> Vec<String> {
    symbols
        .lines()
        .filter_map(|line| line.split_whitespace().last())
        .filter(|name| !name.is_empty() && !name.starts_with('$'))
        .take(120)
        .map(str::to_string)
        .collect()
}

fn menu_hints(strings: &str) -> Vec<String> {
    strings
        .lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            lower.contains("choice")
                || lower.contains("menu")
                || lower.contains("exit")
                || lower.contains("add")
                || lower.contains("delete")
                || lower.contains("free")
        })
        .take(80)
        .map(str::to_string)
        .collect()
}

fn allocator_hints(symbols: &str) -> Vec<String> {
    symbols
        .lines()
        .filter(|line| {
            ["malloc", "calloc", "realloc", "free"]
                .iter()
                .any(|needle| line.contains(needle))
        })
        .take(80)
        .map(str::to_string)
        .collect()
}

fn run_revng(binary: &Path, function: Option<&str>, options: &RevngOptions) -> Value {
    match run_revng_inner(binary, function, options) {
        Ok(output) => json!({"ok": true, "output": output.chars().take(12000).collect::<String>()}),
        Err(error) => json!({
            "ok": false,
            "error": error.to_string(),
            "next": "Run `kuzushi mcp health revng` to verify native rev.ng, Docker/Podman, and the rev.ng image.",
        }),
    }
}

fn run_revng_inner(
    binary: &Path,
    function: Option<&str>,
    options: &RevngOptions,
) -> Result<String> {
    let output = if let Some(revng) = native_revng(options)? {
        run_native_revng(&revng, binary)?
    } else {
        run_container_revng(binary, options)?
    };
    Ok(function
        .map(|name| extract_revng_function_excerpt(&output, name))
        .unwrap_or(output))
}

fn run_container_revng(binary: &Path, options: &RevngOptions) -> Result<String> {
    let runtime = container_runtime(options).context("no Docker/Podman runtime found")?;
    let parent = binary.parent().context("binary path has no parent")?;
    let name = binary
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .context("binary file name is not UTF-8")?;
    let args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "--pull=never".to_string(),
        "-v".to_string(),
        format!("{}:/input:ro", parent.display()),
        options.image.clone(),
        "revng".to_string(),
        "artifact".to_string(),
        "--analyze".to_string(),
        "decompile-to-single-file".to_string(),
        format!("/input/{name}"),
    ];
    let output = Command::new(runtime)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("could not run rev.ng container")?;
    if !output.status.success() {
        anyhow::bail!(
            "rev.ng container exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn run_native_revng(revng: &Path, binary: &Path) -> Result<String> {
    let args = vec![
        "artifact".to_string(),
        "--analyze".to_string(),
        "decompile-to-single-file".to_string(),
        binary.display().to_string(),
    ];
    let output = Command::new(revng)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("could not run native rev.ng at {}", revng.display()))?;
    if !output.status.success() {
        anyhow::bail!(
            "native rev.ng exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn extract_revng_function_excerpt(output: &str, function: &str) -> String {
    let Some(name_at) = output.find(function) else {
        return format!(
            "rev.ng decompiled the binary, but no symbol/function matching {function:?} was found.\n\n{}",
            strip_ptml_excerpt(output, 12_000)
        );
    };
    let start = output[..name_at]
        .rfind("<div data-scope=\"c.function\"")
        .unwrap_or_else(|| name_at.saturating_sub(6000));
    let end = output[name_at..]
        .find("<div data-scope=\"c.function\"")
        .map(|offset| name_at + offset)
        .unwrap_or_else(|| (name_at + 12_000).min(output.len()));
    let excerpt = &output[start..end.min(output.len())];
    strip_ptml_excerpt(excerpt, 12_000)
}

fn strip_ptml_excerpt(input: &str, limit: usize) -> String {
    let mut output = String::new();
    let mut in_tag = false;
    for ch in input.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                output.push(' ');
            }
            _ if !in_tag => output.push(ch),
            _ => {}
        }
        if output.len() >= limit {
            break;
        }
    }
    output
        .replace("&quot;", "\"")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

fn native_revng(options: &RevngOptions) -> Result<Option<PathBuf>> {
    if let Some(path) = explicit_native_revng(options)? {
        return Ok(Some(path));
    }
    if revng_on_path() {
        return Ok(Some(PathBuf::from("revng")));
    }
    Ok(installed_revng().or_else(local_revng))
}

fn explicit_native_revng(options: &RevngOptions) -> Result<Option<PathBuf>> {
    let Some(path) = options.native.as_ref() else {
        return Ok(None);
    };
    if path.is_file() {
        return Ok(Some(path.clone()));
    }
    anyhow::bail!(
        "revngNative points to a missing rev.ng binary: {}",
        path.display()
    );
}

fn revng_on_path() -> bool {
    Command::new("revng")
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn installed_revng() -> Option<PathBuf> {
    let installed = PathBuf::from(std::env::var("HOME").ok()?)
        .join(".local")
        .join("share")
        .join("kuzushi")
        .join("revng")
        .join("revng");
    installed.is_file().then_some(installed)
}

fn local_revng() -> Option<PathBuf> {
    std::env::current_dir()
        .ok()
        .map(|cwd| cwd.join("revng").join("revng"))
        .filter(|path| path.is_file())
}

fn container_runtime(options: &RevngOptions) -> Option<String> {
    if let Some(runtime) = options.container_runtime.as_deref() {
        if !runtime.trim().is_empty() {
            return container_runtime_is_usable(runtime).then(|| runtime.to_string());
        }
    }
    ["podman", "docker"]
        .iter()
        .find(|binary| container_runtime_is_usable(binary))
        .map(|binary| (*binary).to_string())
}

fn container_runtime_is_usable(binary: &str) -> bool {
    Command::new(binary)
        .arg("info")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn wait_or_kill(mut child: std::process::Child, timeout: Duration) -> Result<std::process::Output> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if child.try_wait()?.is_some() {
            return child
                .wait_with_output()
                .context("could not collect process output");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let _ = child.kill();
    child
        .wait_with_output()
        .context("could not collect killed process output")
}

fn merge_json(current: &mut Value, patch: Value) {
    match (current, patch) {
        (Value::Object(current), Value::Object(patch)) => merge_object(current, patch),
        (current, patch) => *current = patch,
    }
}

fn merge_object(current: &mut Map<String, Value>, patch: Map<String, Value>) {
    for (key, value) in patch {
        match current.get_mut(&key) {
            Some(existing) => merge_json(existing, value),
            None => {
                current.insert(key, value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::V2Config;
    use crate::findings::TriageOutcome;
    use crate::runtime::{AgentQueryResponse, TriageRequest};
    use crate::workspace::WorkspaceTarget;
    use std::sync::Mutex;
    use tempfile::tempdir;

    #[test]
    fn pwn_module_registers_expected_tools() {
        let module = pwn_module();
        let names = module
            .tools()
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>();
        assert!(names.contains(&"pwn:profile-binary"));
        assert!(names.contains(&"pwn:reverse"));
        assert!(names.contains(&"pwn:state"));
        assert!(names.contains(&"pwn:calibrate-local"));
        assert!(names.contains(&"pwn:run-candidates"));
        assert!(names.contains(&"pwn:auto-solve"));
        assert!(names.contains(&"pwn:menu-probe"));
        assert!(names.contains(&"pwn:exploit-run"));
        assert!(names.contains(&"pwn:heap-uaf-scan"));
    }

    #[test]
    fn pwn_reverse_declares_revng_options_instead_of_env_knobs() {
        let module = pwn_module();
        let reverse = module
            .tools()
            .iter()
            .find(|tool| tool.name == "pwn:reverse")
            .unwrap();
        let option_names = reverse
            .options
            .iter()
            .map(|option| option.name.as_str())
            .collect::<Vec<_>>();

        assert!(option_names.contains(&"revngImage"));
        assert!(option_names.contains(&"revngNative"));
        assert!(option_names.contains(&"revngContainerRuntime"));
    }

    #[test]
    fn collect_leak_markers_extracts_hex_after_keyword() {
        let text = "[+] heap_base = 0x55557910e000\n[*] libc base = 0x7f8019200000\n";
        let leaks = collect_leak_markers(text);
        assert_eq!(leaks.len(), 2);
        assert_eq!(leaks[0]["value"], "0x55557910e000");
        assert_eq!(leaks[1]["value"], "0x7f8019200000");
    }

    #[test]
    fn extract_flag_marker_recognises_htb_braces() {
        let text = "leaked stack\nFlag: HTB{tcache_uaf_for_the_win}\nbye";
        assert_eq!(
            extract_flag_marker(text).as_deref(),
            Some("HTB{tcache_uaf_for_the_win}")
        );
    }

    #[test]
    fn extract_menu_prompts_picks_numbered_lines() {
        let menu = "Welcome!\n1. Create task\n2. Edit task\n   3. View task\n8. Exit\n";
        let prompts = extract_menu_prompts(menu);
        assert!(prompts.iter().any(|line| line.contains("1. Create task")));
        assert!(prompts.iter().any(|line| line.contains("3. View task")));
        assert!(prompts.iter().any(|line| line.contains("8. Exit")));
    }

    #[test]
    fn heap_uaf_summary_flags_refcount_pattern() {
        let summary = HeapUafSummary {
            malloc_call_sites: 2,
            free_call_sites: 1,
            atomic_decrement_sites: 1,
            atomic_increment_sites: 1,
            post_free_clears: 0,
            uses_pthreads: true,
            uses_pthread_mutex: true,
            likely_refcount_pattern: true,
            likely_uaf_pattern: true,
            likely_threaded: true,
        };
        let hints = suggest_uaf_hints(&summary);
        assert!(hints.iter().any(|h| h.to_lowercase().contains("refcount")));
        assert!(hints.iter().any(|h| h.contains("tcache")));
    }

    #[test]
    fn state_round_trips_candidate_and_failed_strategy() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
        };
        let path = state_path_for(&ctx, "abc").unwrap();
        let mut state = load_or_new_state(
            &path,
            BinaryMetadata {
                path: "bin".to_string(),
                hash: "abc".to_string(),
                arch: None,
                libc: None,
                ld: None,
            },
        )
        .unwrap();
        state.candidate_bases.push(CandidateBase {
            kind: "libc".to_string(),
            value: "0x7ffff7dc0000".to_string(),
            confidence: 0.5,
            source: "leak".to_string(),
        });
        save_state(&path, &state).unwrap();
        let loaded = read_state(&path).unwrap();
        assert_eq!(loaded.candidate_bases.len(), 1);
    }

    #[test]
    fn auto_solve_planner_uses_configured_model() {
        struct RecordingRuntime {
            requests: Mutex<Vec<AgentQueryRequest>>,
        }

        impl AgentRuntime for RecordingRuntime {
            fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
                self.requests.lock().unwrap().push(request);
                Ok(AgentQueryResponse {
                    structured: Some(json!({
                        "strategy": "generic-analysis",
                        "reason": "target should be profiled and reversed before exploit attempts",
                        "exploitPath": "unknown",
                        "nextActions": ["profile binary", "summarize dangerous IO"],
                        "actions": [
                            {
                                "operation": "stop",
                                "reason": "unit test planner response should not run further actions"
                            }
                        ],
                        "confidence": 0.91
                    })),
                    ..AgentQueryResponse::default()
                })
            }

            fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
                anyhow::bail!("triage is not used by pwn auto-solve planner")
            }
        }

        let temp = tempdir().unwrap();
        fs::write(temp.path().join("challenge"), b"\x7fELF").unwrap();

        let mut config = V2Config::default();
        config.model = Some("openai:gpt-test".to_string());
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
            trace: None,
        };
        let runtime = RecordingRuntime {
            requests: Mutex::new(Vec::new()),
        };
        let report = plan_auto_solve_strategy(
            &json!({}),
            &ctx,
            Some(&runtime),
            temp.path(),
            &json!({ "stateId": "state-1", "statePath": "/tmp/state.json" }),
            &json!({ "dangerousIo": ["read"], "functions": ["main"] }),
        )
        .unwrap();

        assert_eq!(report["used"], json!(true));
        assert_eq!(report["model"], json!("openai:gpt-test"));
        let requests = runtime.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].model, "openai:gpt-test");
        assert!(requests[0].structured_output.is_some());
    }

    #[test]
    fn auto_solve_loop_replans_after_observations() {
        struct SequencedRuntime {
            requests: Mutex<Vec<AgentQueryRequest>>,
            responses: Mutex<Vec<Value>>,
        }

        impl AgentRuntime for SequencedRuntime {
            fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
                self.requests.lock().unwrap().push(request);
                let response = self.responses.lock().unwrap().remove(0);
                Ok(AgentQueryResponse {
                    structured: Some(response),
                    ..AgentQueryResponse::default()
                })
            }

            fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
                anyhow::bail!("triage is not used by pwn auto-solve planner")
            }
        }

        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
        };
        let binary = temp.path().join("challenge");
        fs::write(&binary, b"\x7fELF").unwrap();
        let state_path = state_path_for(&ctx, "state-1").unwrap();
        let state = load_or_new_state(
            &state_path,
            BinaryMetadata {
                path: binary.display().to_string(),
                hash: "state-1".to_string(),
                arch: None,
                libc: None,
                ld: None,
            },
        )
        .unwrap();
        save_state(&state_path, &state).unwrap();
        let runtime = SequencedRuntime {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(vec![
                json!({
                    "strategy": "generic-analysis",
                    "reason": "record a fact first",
                    "exploitPath": "unknown",
                    "actions": [{
                        "operation": "record-primitive",
                        "reason": "record observed IO",
                        "primitive": {
                            "kind": "leak",
                            "confidence": 0.4,
                            "evidence": "controlled output path",
                            "remoteSafe": false
                        }
                    }],
                    "confidence": 0.6
                }),
                json!({
                    "strategy": "generic-analysis",
                    "reason": "observations are sufficient for now",
                    "exploitPath": "unknown",
                    "actions": [{
                        "operation": "stop",
                        "reason": "wait for operator review"
                    }],
                    "confidence": 0.7
                }),
            ]),
        };

        let report = run_pwn_observe_replan_loop(
            &runtime,
            "openai:gpt-test",
            temp.path(),
            &binary,
            &json!({ "stateId": "state-1", "statePath": state_path }),
            &json!({ "dangerousIo": ["read"], "functions": ["main"] }),
            &ctx,
        )
        .unwrap();

        let requests = runtime.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].prompt.contains("Prior observations"));
        assert!(requests[1].prompt.contains("controlled output path"));
        assert_eq!(report["iterations"].as_array().unwrap().len(), 2);
        assert_eq!(
            report["actionExecution"]["results"]
                .as_array()
                .unwrap()
                .last()
                .unwrap()["status"],
            json!("stopped")
        );
    }
}

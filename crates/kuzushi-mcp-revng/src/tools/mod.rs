use anyhow::{Context, Result};
use async_trait::async_trait;
use kuzushi_mcp_common::{
    cache::{index_root, read_bounded_file, sha256_hex_bytes, write_atomic_file},
    doctor::which,
    process::{run_bounded_process, sanitize_terminal_text, ProcessLimits},
    read_only_sandbox::{read_only_command, resolve_regular_executable, sandbox_available},
    AuthorizedDirectory, BoundedReadFile, ReadRootCapability, Tool, ToolHandler, ToolRegistry,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::process::Command;

const DEFAULT_REVNG_IMAGE: &str = "revng/revng:latest";
const DEFAULT_REVNG_CONTAINER_PLATFORM: &str = "linux/amd64";
const MAX_BINARY_BYTES: usize = 256 * 1024 * 1024;
const MAX_CACHE_BYTES: usize = 1024 * 1024;
const MAX_HOST_OUTPUT_BYTES: usize = 512 * 1024;
const MAX_STDERR_BYTES: usize = 256 * 1024;
const MAX_PATH_BYTES: usize = 16 * 1024;
const MAX_FUNCTION_BYTES: usize = 1024;
const MAX_NATIVE_EXECUTABLE_BYTES: usize = 512 * 1024 * 1024;
const REVNG_TIMEOUT: Duration = Duration::from_secs(120);
const HOST_TOOL_TIMEOUT: Duration = Duration::from_secs(15);
const CONTAINER_MEMORY_LIMIT: &str = "2g";
const CONTAINER_TMPFS_LIMIT: &str = "256m";
static CONTAINER_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
struct RevngContext {
    read_capability: ReadRootCapability,
}

pub(crate) fn build_registry() -> Result<ToolRegistry> {
    Ok(build_registry_with_capability(
        ReadRootCapability::from_environment()?,
    ))
}

fn build_registry_with_capability(read_capability: ReadRootCapability) -> ToolRegistry {
    let context = RevngContext { read_capability };
    let registry = register_binary_tools(ToolRegistry::new(), &context);
    let registry = register_function_tools(registry, &context);
    register_host_tools(registry, context)
}

fn register_binary_tools(registry: ToolRegistry, context: &RevngContext) -> ToolRegistry {
    registry
        .register(
            descriptor(
                "revng.health",
                "Report container runtime, image, and cache readiness.",
                json!({"type":"object","properties":{}}),
            ),
            HealthTool,
        )
        .register(
            descriptor(
                "revng.analyze_binary",
                "Run rev.ng analysis for an ELF binary and cache the JSON/text output.",
                binary_schema(),
            ),
            AnalyzeBinaryTool(context.clone()),
        )
        .register(
            descriptor(
                "revng.list_functions",
                "List functions discovered by rev.ng for the binary.",
                binary_schema(),
            ),
            ListFunctionsTool(context.clone()),
        )
}

fn register_function_tools(registry: ToolRegistry, context: &RevngContext) -> ToolRegistry {
    registry
        .register(
            descriptor(
                "revng.decompile_function",
                "Return rev.ng decompilation output for one function.",
                function_schema(),
            ),
            DecompileFunctionTool(context.clone()),
        )
        .register(
            descriptor(
                "revng.function_cfg",
                "Return control-flow facts for one function.",
                function_schema(),
            ),
            FunctionCfgTool(context.clone()),
        )
}

fn register_host_tools(registry: ToolRegistry, context: RevngContext) -> ToolRegistry {
    registry
        .register(
            descriptor(
                "revng.strings",
                "Return printable strings from the binary, cached beside rev.ng outputs.",
                binary_schema(),
            ),
            StringsTool(context.clone()),
        )
        .register(
            descriptor(
                "revng.symbols",
                "Return dynamic/static symbols from the binary when available.",
                binary_schema(),
            ),
            SymbolsTool(context),
        )
}

fn descriptor(name: &str, description: &str, input_schema: Value) -> Tool {
    Tool {
        name: name.to_string(),
        description: description.to_string(),
        input_schema,
    }
}

fn binary_schema() -> Value {
    json!({
        "type": "object",
        "required": ["binary"],
        "additionalProperties": false,
        "properties": {
            "binary": {"type": "string", "minLength": 1, "maxLength": MAX_PATH_BYTES, "description": "Absolute or granted-root-relative regular binary. The server copies only this file into private scratch."}
        }
    })
}

fn function_schema() -> Value {
    json!({
        "type": "object",
        "required": ["binary", "function"],
        "additionalProperties": false,
        "properties": {
            "binary": {"type": "string", "minLength": 1, "maxLength": MAX_PATH_BYTES},
            "function": {"type": "string", "minLength": 1, "maxLength": MAX_FUNCTION_BYTES}
        }
    })
}

struct HealthTool;
struct AnalyzeBinaryTool(RevngContext);
struct ListFunctionsTool(RevngContext);
struct DecompileFunctionTool(RevngContext);
struct FunctionCfgTool(RevngContext);
struct StringsTool(RevngContext);
struct SymbolsTool(RevngContext);

#[async_trait]
impl ToolHandler for HealthTool {
    async fn call(&self, _args: Value) -> Result<Value> {
        Ok(serde_json::to_value(health_summary().await)?)
    }
}

#[async_trait]
impl ToolHandler for AnalyzeBinaryTool {
    async fn call(&self, args: Value) -> Result<Value> {
        run_revng_cached(&self.0, &args, RevngAction::Analyze).await
    }
}

#[async_trait]
impl ToolHandler for ListFunctionsTool {
    async fn call(&self, args: Value) -> Result<Value> {
        run_revng_cached(&self.0, &args, RevngAction::ListFunctions).await
    }
}

#[async_trait]
impl ToolHandler for DecompileFunctionTool {
    async fn call(&self, args: Value) -> Result<Value> {
        run_revng_cached(&self.0, &args, RevngAction::Decompile).await
    }
}

#[async_trait]
impl ToolHandler for FunctionCfgTool {
    async fn call(&self, args: Value) -> Result<Value> {
        run_revng_cached(&self.0, &args, RevngAction::Cfg).await
    }
}

#[async_trait]
impl ToolHandler for StringsTool {
    async fn call(&self, args: Value) -> Result<Value> {
        let prepared = prepare_binary_request(&self.0, &args, false)?;
        let output = run_host_tool("strings", [prepared.scratch_path.as_os_str()]).await?;
        Ok(
            json!({"binary": prepared.display_path, "strings": output.lines().take(500).collect::<Vec<_>>() }),
        )
    }
}

#[async_trait]
impl ToolHandler for SymbolsTool {
    async fn call(&self, args: Value) -> Result<Value> {
        let prepared = prepare_binary_request(&self.0, &args, false)?;
        let output = match run_host_tool("nm", [prepared.scratch_path.as_os_str()]).await {
            Ok(output) => output,
            Err(_) => {
                run_host_tool(
                    "readelf",
                    [OsStr::new("-Ws"), prepared.scratch_path.as_os_str()],
                )
                .await?
            }
        };
        Ok(
            json!({"binary": prepared.display_path, "symbols": output.lines().take(1000).collect::<Vec<_>>() }),
        )
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RevngHealth {
    ready: bool,
    mode: Option<String>,
    native_path: Option<String>,
    runtime: Option<String>,
    image: String,
    image_available: bool,
    cache_path: String,
    missing: Vec<String>,
}

pub(crate) async fn health_summary() -> RevngHealth {
    let native = native_revng();
    let native_sandbox_ready = sandbox_available().await;
    let runtime = container_runtime().await;
    let image = revng_image();
    let cache_path = revng_cache_root()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "<unavailable>".to_string());
    let image_available = match runtime.as_deref() {
        Some(runtime) => image_exists(runtime, &image).await,
        None => false,
    };
    let mode = health_mode(
        native.is_some(),
        native_sandbox_ready,
        runtime.is_some(),
        image_available,
    );
    let missing = health_missing(
        native.is_some(),
        native_sandbox_ready,
        runtime.is_some(),
        image_available,
        &image,
    );
    RevngHealth {
        ready: mode.is_some(),
        mode,
        native_path: native.map(|path| path.display().to_string()),
        runtime,
        image,
        image_available,
        cache_path,
        missing,
    }
}

fn health_mode(native: bool, sandbox: bool, runtime: bool, image: bool) -> Option<String> {
    if runtime && image {
        Some("container".to_string())
    } else if native && sandbox {
        Some("native".to_string())
    } else {
        None
    }
}

fn health_missing(
    native: bool,
    sandbox: bool,
    runtime: bool,
    image_available: bool,
    image: &str,
) -> Vec<String> {
    let mut missing = Vec::new();
    if !native && !runtime {
        missing.push("native-revng-or-docker-or-podman".to_string());
    }
    if native && !sandbox && !(runtime && image_available) {
        missing.push("read-only-process-sandbox".to_string());
    }
    if !native && runtime && !image_available {
        missing.push(image.to_string());
    }
    missing
}

#[derive(Clone, Copy)]
enum RevngAction {
    Analyze,
    ListFunctions,
    Decompile,
    Cfg,
}

impl RevngAction {
    fn cache_name(self) -> &'static str {
        match self {
            Self::Analyze => "analyze",
            Self::ListFunctions => "functions",
            Self::Decompile => "decompile",
            Self::Cfg => "cfg",
        }
    }

    fn container_args(self, binary_name: &str) -> Vec<String> {
        let binary = format!("/input/{binary_name}");
        match self {
            Self::Analyze | Self::ListFunctions | Self::Decompile => {
                vec![
                    "revng".into(),
                    "artifact".into(),
                    "decompile-to-single-file".into(),
                    binary,
                ]
            }
            Self::Cfg => {
                vec![
                    "revng".into(),
                    "artifact".into(),
                    "render-svg-cfg".into(),
                    binary,
                ]
            }
        }
    }

    fn native_args(self, binary: &Path) -> Vec<String> {
        let binary = binary.display().to_string();
        match self {
            Self::Analyze | Self::ListFunctions | Self::Decompile => {
                vec!["artifact".into(), "decompile-to-single-file".into(), binary]
            }
            Self::Cfg => {
                vec!["artifact".into(), "render-svg-cfg".into(), binary]
            }
        }
    }
}

async fn run_revng_cached(
    context: &RevngContext,
    args: &Value,
    action: RevngAction,
) -> Result<Value> {
    let requires_function = matches!(action, RevngAction::Decompile | RevngAction::Cfg);
    let prepared = prepare_binary_request(context, args, requires_function)?;
    let function = optional_function(args, requires_function)?;
    let backend = select_backend().await?;
    let cache_file = cache_file_for(
        &prepared.sha256,
        &backend.cache_key,
        action,
        function.as_deref(),
    )?;
    if let Some(output) = read_cached_output(&cache_file)? {
        return Ok(revng_output_json(
            &prepared,
            &backend,
            &cache_file,
            true,
            output,
        ));
    }

    let raw_output = execute_backend(&backend, &prepared, action).await?;
    let output = normalize_action_output(raw_output, function.as_deref(), action);
    verify_backend_identity(&backend)?;
    write_atomic_file(&cache_file, output.as_bytes(), MAX_CACHE_BYTES)?;
    Ok(revng_output_json(
        &prepared,
        &backend,
        &cache_file,
        false,
        output,
    ))
}

async fn execute_backend(
    backend: &RevngBackend,
    prepared: &PreparedBinary,
    action: RevngAction,
) -> Result<String> {
    let output = match &backend.kind {
        RevngBackendKind::Native { path, .. } => {
            run_revng_native(path, &prepared.scratch_path, action).await?
        }
        RevngBackendKind::Container { runtime, image } => {
            run_revng_container(runtime, image, &prepared, action).await?
        }
    };
    Ok(output)
}

fn normalize_action_output(
    raw_output: String,
    function: Option<&str>,
    action: RevngAction,
) -> String {
    let raw_output = if raw_output.trim().is_empty() {
        empty_revng_output_message(action)
    } else {
        raw_output
    };
    function
        .map(|name| extract_revng_function_excerpt(&raw_output, name))
        .unwrap_or(raw_output)
}

fn read_cached_output(cache_file: &Path) -> Result<Option<String>> {
    read_bounded_file(cache_file, MAX_CACHE_BYTES)?
        .map(String::from_utf8)
        .transpose()
        .with_context(|| format!("rev.ng cache is not UTF-8: {}", cache_file.display()))
}

fn empty_revng_output_message(action: RevngAction) -> String {
    format!(
        "rev.ng completed {} successfully but produced no stdout for this binary. This can happen for stripped or unsupported binaries; use revng.symbols or revng.strings for host-observable facts.",
        action.cache_name()
    )
}

fn revng_output_json(
    binary: &PreparedBinary,
    backend: &RevngBackend,
    cache_file: &Path,
    cached: bool,
    output: String,
) -> Value {
    json!({
        "binary": binary.display_path,
        "backend": backend.label,
        "cached": cached,
        "cacheFile": cache_file.display().to_string(),
        "output": output,
    })
}

struct PreparedBinary {
    display_path: String,
    scratch_path: PathBuf,
    sha256: String,
    _scratch: tempfile::TempDir,
}

fn prepare_binary_request(
    context: &RevngContext,
    args: &Value,
    function_required: bool,
) -> Result<PreparedBinary> {
    validate_arguments(args, function_required)?;
    let raw = required_string(args, "binary", MAX_PATH_BYTES)?;
    let opened = context
        .read_capability
        .open_strict(Path::new(raw), MAX_BINARY_BYTES)?;
    PreparedBinary::from_opened(opened)
}

impl PreparedBinary {
    fn from_opened(opened: BoundedReadFile) -> Result<Self> {
        let display_path = sanitize_terminal_text(&opened.path().display().to_string());
        let scratch = tempfile::Builder::new()
            .prefix("kuzushi-revng-")
            .tempdir()?;
        let scratch_path = scratch.path().join("input.bin");
        let mut output = private_scratch_file(&scratch_path)?;
        let sha256 = opened.copy_to_with_sha256_hex(&mut output)?;
        output.flush()?;
        output.sync_all()?;
        Ok(Self {
            display_path,
            scratch_path,
            sha256,
            _scratch: scratch,
        })
    }
}

fn private_scratch_file(path: &Path) -> Result<fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .context("could not create private rev.ng input")
}

fn validate_arguments(args: &Value, function_required: bool) -> Result<()> {
    let object = args
        .as_object()
        .context("rev.ng arguments must be an object")?;
    let allowed = if function_required {
        &["binary", "function"][..]
    } else {
        &["binary"][..]
    };
    if let Some(name) = object.keys().find(|name| !allowed.contains(&name.as_str())) {
        anyhow::bail!("unknown rev.ng argument: {name}");
    }
    Ok(())
}

fn optional_function(args: &Value, required: bool) -> Result<Option<String>> {
    match (args.get("function"), required) {
        (Some(_), _) => Ok(Some(
            required_string(args, "function", MAX_FUNCTION_BYTES)?.to_string(),
        )),
        (None, true) => anyhow::bail!("missing required function"),
        (None, false) => Ok(None),
    }
}

fn required_string<'a>(args: &'a Value, name: &str, max_bytes: usize) -> Result<&'a str> {
    let value = args
        .get(name)
        .and_then(Value::as_str)
        .with_context(|| format!("missing required {name}"))?;
    anyhow::ensure!(!value.is_empty(), "{name} must not be empty");
    anyhow::ensure!(
        value.len() <= max_bytes,
        "{name} exceeds the {max_bytes}-byte limit"
    );
    anyhow::ensure!(
        !value.chars().any(char::is_control),
        "{name} contains control characters"
    );
    Ok(value)
}

struct RevngBackend {
    kind: RevngBackendKind,
    label: String,
    cache_key: String,
}

enum RevngBackendKind {
    Native { path: PathBuf, sha256: String },
    Container { runtime: String, image: String },
}

async fn select_backend() -> Result<RevngBackend> {
    let image = revng_image();
    if let Some(runtime) = container_runtime().await {
        return container_backend(runtime, image).await;
    }
    let path = native_revng().context(
        "rev.ng MCP requires a verified local container image or a sandboxed native revng executable",
    )?;
    native_backend(path).await
}

async fn native_backend(path: PathBuf) -> Result<RevngBackend> {
    anyhow::ensure!(
        sandbox_available().await,
        "native rev.ng refused: no verified read-only process sandbox is available"
    );
    let path = resolve_regular_executable(path.as_os_str())?;
    let sha256 = native_executable_sha256(&path)?;
    Ok(RevngBackend {
        label: format!("native:{}", path.display()),
        cache_key: native_cache_key(&path, &sha256),
        kind: RevngBackendKind::Native { path, sha256 },
    })
}

fn native_cache_key(path: &Path, sha256: &str) -> String {
    format!("native:{}:{sha256}", path.display())
}

async fn container_backend(runtime: String, configured_image: String) -> Result<RevngBackend> {
    let image = container_image_identity(&runtime, &configured_image).await?;
    Ok(RevngBackend {
        label: format!("container:{runtime}:{configured_image}@{image}"),
        cache_key: format!("container:{image}"),
        kind: RevngBackendKind::Container { runtime, image },
    })
}

async fn run_revng_native(revng: &Path, binary: &Path, action: RevngAction) -> Result<String> {
    let input = authorize_file_parent(binary)?;
    let mut sandboxed = read_only_command(revng, action.native_args(binary), input).await?;
    sandboxed
        .command_mut()?
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = run_bounded_process(
        sandboxed.command_mut()?,
        "sandboxed native rev.ng",
        revng_limits(),
    )
    .await?;
    if !output.status.success() {
        anyhow::bail!(
            "native rev.ng exited with {}: {}",
            output.status,
            output.stderr
        );
    }
    Ok(output.stdout)
}

async fn run_revng_container(
    runtime: &str,
    image: &str,
    binary: &PreparedBinary,
    action: RevngAction,
) -> Result<String> {
    let binary_dir = binary
        .scratch_path
        .parent()
        .context("private binary path has no parent directory")?;
    let binary_name = binary
        .scratch_path
        .file_name()
        .and_then(OsStr::to_str)
        .context("binary file name is not valid UTF-8")?;
    let volume = format!("{}:/input:ro", binary_dir.display());
    let mut cleanup = ContainerCleanup::new(runtime)?;
    let mut command =
        revng_container_command(runtime, image, &volume, binary_name, cleanup.name(), action);
    let run = run_bounded_process(&mut command, "rev.ng container", revng_limits()).await;
    let removed = cleanup.remove().await;
    let output = combine_container_result(run, removed)?;
    if !output.status.success() {
        anyhow::bail!(
            "rev.ng container exited with {}: {}",
            output.status,
            output.stderr
        );
    }
    Ok(output.stdout)
}

fn revng_container_command(
    runtime: &str,
    image: &str,
    volume: &str,
    binary_name: &str,
    container_name: &str,
    action: RevngAction,
) -> Command {
    let mut command = Command::new(runtime);
    command.arg("run");
    append_container_isolation(&mut command, container_name);
    append_container_resources(&mut command);
    command
        .args(container_platform_args())
        .arg("-v")
        .arg(volume)
        .arg(image)
        .args(action.container_args(binary_name))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn append_container_isolation(command: &mut Command, container_name: &str) {
    command
        .arg("--rm")
        .arg("--pull=never")
        .arg("--name")
        .arg(container_name)
        .arg("--network=none")
        .arg("--cap-drop=ALL")
        .arg("--security-opt=no-new-privileges")
        .arg("--read-only")
        .arg("--env")
        .arg("HOME=/tmp")
        .arg("--env")
        .arg("XDG_CACHE_HOME=/tmp");
}

fn append_container_resources(command: &mut Command) {
    command
        .arg("--memory")
        .arg(CONTAINER_MEMORY_LIMIT)
        .arg("--pids-limit")
        .arg("256")
        .arg("--cpus")
        .arg("2")
        .arg("--tmpfs")
        .arg(format!(
            "/tmp:rw,noexec,nosuid,size={CONTAINER_TMPFS_LIMIT}"
        ));
}

fn combine_container_result(
    run: Result<kuzushi_mcp_common::process::BoundedProcessOutput>,
    removed: Result<()>,
) -> Result<kuzushi_mcp_common::process::BoundedProcessOutput> {
    match (run, removed) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(cleanup)) => Err(cleanup.context("rev.ng container cleanup failed")),
        (Err(error), Err(cleanup)) => Err(cleanup.context(error)),
    }
}

struct ContainerCleanup {
    runtime: String,
    name: String,
    armed: bool,
    #[cfg(unix)]
    parent_death_guard: ContainerParentDeathGuard,
}

impl ContainerCleanup {
    fn new(runtime: &str) -> Result<Self> {
        let sequence = CONTAINER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = format!("kuzushi-revng-{}-{sequence}", std::process::id());
        Ok(Self {
            runtime: runtime.to_string(),
            #[cfg(unix)]
            parent_death_guard: ContainerParentDeathGuard::spawn(runtime, &name)?,
            name,
            armed: true,
        })
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn remove(&mut self) -> Result<()> {
        self.remove_with_limits(cleanup_limits()).await
    }

    async fn remove_with_limits(&mut self, limits: ProcessLimits) -> Result<()> {
        let mut command = force_remove_command(&self.runtime, &self.name);
        let output = run_bounded_process(&mut command, "rev.ng container cleanup", limits).await?;
        anyhow::ensure!(
            output.status.success() || container_is_absent(&output.stderr),
            "rev.ng container cleanup exited with {}: {}",
            output.status,
            output.stderr
        );
        self.armed = false;
        #[cfg(unix)]
        self.parent_death_guard.disarm();
        Ok(())
    }
}

fn container_is_absent(stderr: &str) -> bool {
    let message = stderr.to_ascii_lowercase();
    [
        "no such container",
        "does not exist",
        "no container with name or id",
        "container not found",
    ]
    .iter()
    .any(|needle| message.contains(needle))
}

impl Drop for ContainerCleanup {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        #[cfg(unix)]
        return;
        #[cfg(not(unix))]
        {
            let runtime = self.runtime.clone();
            let name = self.name.clone();
            std::thread::spawn(move || bounded_force_remove(&runtime, &name));
        }
    }
}

#[cfg(unix)]
struct ContainerParentDeathGuard {
    process: Option<std::process::Child>,
    keepalive: Option<std::process::ChildStdin>,
}

#[cfg(unix)]
impl ContainerParentDeathGuard {
    fn spawn(runtime: &str, name: &str) -> Result<Self> {
        let script = "trap '' HUP INT TERM\nif IFS= read -r command; then\n  [ \"$command\" = disarm ] && exit 0\nfi\nexec \"$1\" rm -f \"$2\"\n";
        let mut command = std::process::Command::new("/bin/sh");
        command
            .args(["-c", script, "kuzushi-revng-container-guard", runtime, name])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_cleanup_group(&mut command);
        let mut process = command
            .spawn()
            .context("spawn rev.ng container parent-death cleanup guard")?;
        let keepalive = process
            .stdin
            .take()
            .context("rev.ng container cleanup guard has no stdin")?;
        Ok(Self {
            process: Some(process),
            keepalive: Some(keepalive),
        })
    }

    fn disarm(&mut self) {
        if let Some(mut keepalive) = self.keepalive.take() {
            let _ = keepalive.write_all(b"disarm\n");
        }
        if let Some(mut process) = self.process.take() {
            wait_for_cleanup(&mut process, Duration::from_secs(5));
        }
    }
}

#[cfg(unix)]
impl Drop for ContainerParentDeathGuard {
    fn drop(&mut self) {
        self.keepalive.take();
        if let Some(mut process) = self.process.take() {
            std::thread::spawn(move || wait_for_cleanup(&mut process, Duration::from_secs(5)));
        }
    }
}

fn force_remove_command(runtime: &str, name: &str) -> Command {
    let mut command = Command::new(runtime);
    command
        .arg("rm")
        .arg("-f")
        .arg(name)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

#[cfg(not(unix))]
fn bounded_force_remove(runtime: &str, name: &str) {
    let mut command = std::process::Command::new(runtime);
    command
        .arg("rm")
        .arg("-f")
        .arg(name)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    configure_cleanup_group(&mut command);
    if let Ok(mut child) = command.spawn() {
        wait_for_cleanup(&mut child, Duration::from_secs(5));
    }
}

fn wait_for_cleanup(child: &mut std::process::Child, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    kill_cleanup_group(child.id());
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
fn configure_cleanup_group(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_cleanup_group(_command: &mut std::process::Command) {}

#[cfg(unix)]
fn kill_cleanup_group(group_id: u32) {
    // SAFETY: cleanup was assigned a dedicated process group before spawn.
    unsafe {
        libc::killpg(group_id as libc::pid_t, libc::SIGKILL);
    }
}

#[cfg(not(unix))]
fn kill_cleanup_group(_group_id: u32) {}

fn container_platform_args() -> Vec<String> {
    let platform = std::env::var("KUZUSHI_REVNG_CONTAINER_PLATFORM")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_REVNG_CONTAINER_PLATFORM.to_string());
    if platform.eq_ignore_ascii_case("none") {
        Vec::new()
    } else {
        vec!["--platform".to_string(), platform]
    }
}

fn extract_revng_function_excerpt(output: &str, function: &str) -> String {
    let Some(name_at) = output.find(function) else {
        return format!(
            "rev.ng decompiled the binary, but no symbol/function matching {function:?} was found.\n\n{}",
            strip_ptml_excerpt(output, 24_000)
        );
    };
    let approximate_start = output[..name_at]
        .rfind("<div data-scope=\"c.function\"")
        .unwrap_or_else(|| name_at.saturating_sub(12_000));
    let approximate_end = output[name_at..]
        .find("<div data-scope=\"c.function\"")
        .map(|offset| name_at + offset)
        .unwrap_or_else(|| (name_at + 24_000).min(output.len()));
    let start = floor_char_boundary(output, approximate_start);
    let end = floor_char_boundary(output, approximate_end.min(output.len()));
    strip_ptml_excerpt(&output[start..end], 24_000)
}

fn floor_char_boundary(input: &str, index: usize) -> usize {
    let mut boundary = index.min(input.len());
    while boundary > 0 && !input.is_char_boundary(boundary) {
        boundary -= 1;
    }
    boundary
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

fn revng_image() -> String {
    std::env::var("KUZUSHI_REVNG_IMAGE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_REVNG_IMAGE.to_string())
}

fn native_revng() -> Option<PathBuf> {
    configured_native_revng()
        .or_else(|| which("revng"))
        .or_else(installed_native_revng)
}

fn configured_native_revng() -> Option<PathBuf> {
    std::env::var("KUZUSHI_REVNG_NATIVE")
        .ok()
        .map(|value| PathBuf::from(value.trim()))
        .filter(|path| path.is_file())
}

fn installed_native_revng() -> Option<PathBuf> {
    let home = PathBuf::from(std::env::var("HOME").ok()?);
    let installed = home.join(".local/share/kuzushi/revng/revng");
    installed.is_file().then_some(installed)
}

fn native_executable_sha256(path: &Path) -> Result<String> {
    let parent = path
        .parent()
        .context("native rev.ng executable has no parent directory")?;
    let capability = ReadRootCapability::new([parent.to_path_buf()])?;
    capability
        .open_strict(path, MAX_NATIVE_EXECUTABLE_BYTES)?
        .copy_to_with_sha256_hex(&mut std::io::sink())
}

fn verify_backend_identity(backend: &RevngBackend) -> Result<()> {
    if let RevngBackendKind::Native { path, sha256 } = &backend.kind {
        anyhow::ensure!(
            native_executable_sha256(path)? == *sha256,
            "native rev.ng executable changed while analysis was running"
        );
    }
    Ok(())
}

async fn container_runtime() -> Option<String> {
    if let Some(runtime) = configured_container_runtime() {
        return Some(runtime);
    }
    first_usable_container_runtime().await
}

fn configured_container_runtime() -> Option<String> {
    std::env::var("KUZUSHI_REVNG_CONTAINER_RUNTIME")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

async fn first_usable_container_runtime() -> Option<String> {
    for binary in ["podman", "docker"] {
        if container_runtime_is_usable(binary).await {
            return Some(binary.to_string());
        }
    }
    None
}

async fn container_runtime_is_usable(binary: &str) -> bool {
    if which(binary).is_none() {
        return false;
    }
    let mut command = Command::new(binary);
    command
        .arg("info")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_bounded_process(&mut command, "container runtime probe", host_limits())
        .await
        .map(|output| output.status.success())
        .unwrap_or(false)
}

async fn image_exists(runtime: &str, image: &str) -> bool {
    container_image_identity(runtime, image).await.is_ok()
}

async fn container_image_identity(runtime: &str, image: &str) -> Result<String> {
    let mut command = Command::new(runtime);
    command
        .arg("image")
        .arg("inspect")
        .arg("--format")
        .arg("{{.Id}}")
        .arg(image)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output =
        run_bounded_process(&mut command, "container image identity", host_limits()).await?;
    anyhow::ensure!(
        output.status.success(),
        "container image identity lookup exited with {}: {}",
        output.status,
        output.stderr
    );
    normalize_container_image_id(output.stdout.trim())
}

fn normalize_container_image_id(value: &str) -> Result<String> {
    let digest = value.strip_prefix("sha256:").unwrap_or(value);
    anyhow::ensure!(
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "container image inspect returned an invalid immutable image ID"
    );
    Ok(format!("sha256:{}", digest.to_ascii_lowercase()))
}

fn revng_cache_root() -> Result<PathBuf> {
    Ok(index_root()?.join("revng"))
}

fn cache_file_for(
    binary_hash: &str,
    image: &str,
    action: RevngAction,
    function: Option<&str>,
) -> Result<PathBuf> {
    let image_key = sha256_hex_bytes(image.as_bytes());
    let function_key = function
        .map(|value| sha256_hex_bytes(value.as_bytes()))
        .unwrap_or_else(|| "all".to_string());
    Ok(revng_cache_root()?
        .join(binary_hash)
        .join(image_key)
        .join(format!("{}-{function_key}.txt", action.cache_name())))
}

async fn run_host_tool<I, S>(binary: &str, args: I) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args = args
        .into_iter()
        .map(|argument| argument.as_ref().to_owned())
        .collect::<Vec<_>>();
    let input_path = args
        .last()
        .map(Path::new)
        .context("host parser requires an input path")?;
    let input = authorize_file_parent(input_path)?;
    let program = resolve_regular_executable(OsStr::new(binary))?;
    let mut sandboxed = read_only_command(&program, &args, input).await?;
    sandboxed
        .command_mut()?
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = run_bounded_process(sandboxed.command_mut()?, binary, host_limits()).await?;
    if !output.status.success() {
        anyhow::bail!(
            "`{binary}` exited with {}: {}",
            output.status,
            output.stderr
        );
    }
    Ok(output.stdout)
}

fn authorize_file_parent(path: &Path) -> Result<AuthorizedDirectory> {
    let parent = path
        .parent()
        .context("sandboxed input has no parent directory")?;
    ReadRootCapability::new([parent.to_path_buf()])?.authorize_directory(parent)
}

fn revng_limits() -> ProcessLimits {
    ProcessLimits {
        timeout: REVNG_TIMEOUT,
        stdout_bytes: MAX_CACHE_BYTES,
        stderr_bytes: MAX_STDERR_BYTES,
    }
}

fn host_limits() -> ProcessLimits {
    ProcessLimits {
        timeout: HOST_TOOL_TIMEOUT,
        stdout_bytes: MAX_HOST_OUTPUT_BYTES,
        stderr_bytes: MAX_STDERR_BYTES,
    }
}

fn cleanup_limits() -> ProcessLimits {
    ProcessLimits {
        timeout: Duration::from_secs(5),
        stdout_bytes: 64 * 1024,
        stderr_bytes: 64 * 1024,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    const REVNG_GUARD_RUNTIME_ENV: &str = "KUZUSHI_REVNG_GUARD_TEST_RUNTIME";
    #[cfg(unix)]
    const REVNG_GUARD_READY_ENV: &str = "KUZUSHI_REVNG_GUARD_TEST_READY";
    #[cfg(unix)]
    const REVNG_GUARD_CLEANED_ENV: &str = "KUZUSHI_REVNG_GUARD_TEST_CLEANED";

    #[test]
    fn registry_exposes_revng_tools() {
        let root = tempfile::tempdir().unwrap();
        let capability = ReadRootCapability::new([root.path().to_path_buf()]).unwrap();
        let registry = build_registry_with_capability(capability);
        for name in [
            "revng.health",
            "revng.analyze_binary",
            "revng.list_functions",
            "revng.decompile_function",
            "revng.function_cfg",
            "revng.strings",
            "revng.symbols",
        ] {
            assert!(registry.contains(name), "{name} should be registered");
        }
    }

    #[tokio::test]
    async fn registry_rejects_binary_outside_the_granted_root() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let capability = ReadRootCapability::new([root.path().to_path_buf()]).unwrap();
        let registry = build_registry_with_capability(capability);

        let error = registry
            .call(
                "revng.strings",
                json!({"binary": outside.path().display().to_string()}),
            )
            .await
            .unwrap_err();

        assert!(error.to_string().contains("outside the MCP read roots"));
    }

    #[test]
    fn caller_selected_container_images_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let binary = root.path().join("sample.elf");
        fs::write(&binary, b"ELF").unwrap();
        let context = RevngContext {
            read_capability: ReadRootCapability::new([root.path().to_path_buf()]).unwrap(),
        };

        let error = prepare_binary_request(
            &context,
            &json!({"binary": binary.display().to_string(), "image": "attacker:latest"}),
            false,
        )
        .err()
        .expect("caller image must be rejected");

        assert!(error.to_string().contains("unknown rev.ng argument: image"));
    }

    #[test]
    fn prepared_binary_scratch_contains_no_source_siblings() {
        let root = tempfile::tempdir().unwrap();
        let binary = root.path().join("sample.elf");
        fs::write(&binary, b"ELF").unwrap();
        fs::write(root.path().join("secret.txt"), b"do not mount").unwrap();
        let context = RevngContext {
            read_capability: ReadRootCapability::new([root.path().to_path_buf()]).unwrap(),
        };

        let prepared = prepare_binary_request(
            &context,
            &json!({"binary": binary.display().to_string()}),
            false,
        )
        .unwrap();
        let entries = fs::read_dir(prepared.scratch_path.parent().unwrap())
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].file_name(), "input.bin");
        assert_eq!(fs::read(&prepared.scratch_path).unwrap(), b"ELF");
    }

    #[tokio::test]
    async fn health_reports_missing_runtime_without_panicking() {
        let health = health_summary().await;
        assert!(!health.cache_path.is_empty());
    }

    #[test]
    fn container_artifact_args_match_current_revng_cli() {
        let args = RevngAction::Analyze.container_args("sample.elf");
        assert_eq!(
            args,
            vec![
                "revng",
                "artifact",
                "decompile-to-single-file",
                "/input/sample.elf"
            ]
        );
        assert!(!args.iter().any(|arg| arg == "--analyze"));
    }

    #[test]
    fn native_artifact_args_match_current_revng_cli() {
        let args = RevngAction::Cfg.native_args(Path::new("/tmp/sample.elf"));
        assert_eq!(args, vec!["artifact", "render-svg-cfg", "/tmp/sample.elf"]);
        assert!(!args.iter().any(|arg| arg == "--analyze"));
    }

    #[test]
    fn empty_output_message_names_follow_up_tools() {
        let message = empty_revng_output_message(RevngAction::ListFunctions);
        assert!(message.contains("revng.symbols"));
        assert!(message.contains("revng.strings"));
    }

    #[test]
    fn function_excerpt_clamps_multibyte_boundaries() {
        let output = format!("{}atarget() {{}}", "é".repeat(7_000));

        let excerpt = extract_revng_function_excerpt(&output, "target");

        assert!(excerpt.contains("target"));
    }

    #[test]
    fn oversized_binary_is_rejected_before_scratch_copy() {
        let root = tempfile::tempdir().unwrap();
        let binary = root.path().join("huge.elf");
        let file = fs::File::create(&binary).unwrap();
        file.set_len((MAX_BINARY_BYTES + 1) as u64).unwrap();
        let context = RevngContext {
            read_capability: ReadRootCapability::new([root.path().to_path_buf()]).unwrap(),
        };

        let error = prepare_binary_request(
            &context,
            &json!({"binary": binary.display().to_string()}),
            false,
        )
        .err()
        .expect("oversized binary must fail");

        assert!(error.to_string().contains("268435456 bytes"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failing_container_is_force_removed_with_bounded_resource_flags() {
        let (root, runtime, binary_path, prepared) = failing_container_fixture();

        let error = run_revng_container(
            runtime.to_str().unwrap(),
            "operator/image@sha256:abc",
            &prepared,
            RevngAction::Analyze,
        )
        .await
        .unwrap_err();
        let arguments = fs::read_to_string(root.path().join("args.log")).unwrap();

        assert!(error.to_string().contains("exited with"));
        assert_container_isolation_arguments(&arguments, &binary_path, &prepared);
    }

    #[cfg(unix)]
    fn failing_container_fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PreparedBinary) {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let runtime = root.path().join("fake-runtime");
        fs::write(
            &runtime,
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$(dirname \"$0\")/args.log\"\n[ \"$1\" = run ] && exit 7\nexit 0\n",
        )
        .unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let binary = root.path().join("sample.elf");
        fs::write(&binary, b"ELF").unwrap();
        let context = RevngContext {
            read_capability: ReadRootCapability::new([root.path().to_path_buf()]).unwrap(),
        };
        let prepared = prepare_binary_request(
            &context,
            &json!({"binary": binary.display().to_string()}),
            false,
        )
        .unwrap();
        (root, runtime, binary, prepared)
    }

    #[cfg(unix)]
    fn assert_container_isolation_arguments(
        arguments: &str,
        binary_path: &Path,
        prepared: &PreparedBinary,
    ) {
        for required in [
            "--pull=never",
            "--network=none",
            "--read-only",
            "--memory",
            CONTAINER_MEMORY_LIMIT,
            "--pids-limit",
            "--cpus",
            "--tmpfs",
            "rm",
            "-f",
        ] {
            assert!(
                arguments.lines().any(|line| line == required),
                "missing {required}: {arguments}"
            );
        }
        assert!(!arguments.contains(&binary_path.parent().unwrap().display().to_string()));
        assert!(arguments.contains(
            &prepared
                .scratch_path
                .parent()
                .unwrap()
                .display()
                .to_string()
        ));
    }

    #[cfg(unix)]
    #[test]
    fn native_cache_key_changes_when_the_executable_bytes_change() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let executable = root.path().join("revng");
        fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let canonical = fs::canonicalize(&executable).unwrap();
        let first = native_cache_key(&canonical, &native_executable_sha256(&canonical).unwrap());

        fs::write(&executable, "#!/bin/sh\nexit 1\n").unwrap();
        let second = native_cache_key(&canonical, &native_executable_sha256(&canonical).unwrap());

        assert_ne!(first, second);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn mutable_container_tag_cache_key_tracks_the_inspected_image_id() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let runtime = root.path().join("fake-runtime");
        let identity = root.path().join("identity");
        fs::write(&runtime, "#!/bin/sh\ncat \"$(dirname \"$0\")/identity\"\n").unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&identity, format!("sha256:{}\n", "a".repeat(64))).unwrap();
        let first = container_backend(
            runtime.display().to_string(),
            "operator/revng:mutable".to_string(),
        )
        .await
        .unwrap();

        fs::write(&identity, format!("sha256:{}\n", "b".repeat(64))).unwrap();
        let second = container_backend(
            runtime.display().to_string(),
            "operator/revng:mutable".to_string(),
        )
        .await
        .unwrap();

        assert_ne!(first.cache_key, second.cache_key);
        assert!(matches!(
            second.kind,
            RevngBackendKind::Container { ref image, .. }
                if image == &format!("sha256:{}", "b".repeat(64))
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_container_removal_stays_armed_and_drop_retries() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let runtime = root.path().join("fake-runtime");
        let calls = root.path().join("calls");
        fs::write(
            &runtime,
            "#!/bin/sh\ndir=$(dirname \"$0\"); printf x >> \"$dir/calls\"; if [ ! -e \"$dir/once\" ]; then : > \"$dir/once\"; exit 7; fi; exit 0\n",
        )
        .unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let mut cleanup = ContainerCleanup::new(runtime.to_str().unwrap()).unwrap();

        assert!(cleanup.remove().await.is_err());
        assert!(cleanup.armed);
        drop(cleanup);

        wait_for_call_count(&calls, 2).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timed_out_container_removal_stays_armed_and_drop_retries() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let runtime = root.path().join("fake-runtime");
        let calls = root.path().join("calls");
        fs::write(
            &runtime,
            "#!/bin/sh\ndir=$(dirname \"$0\"); printf x >> \"$dir/calls\"; if [ -e \"$dir/sleep-once\" ]; then rm \"$dir/sleep-once\"; sleep 30; fi; exit 0\n",
        )
        .unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.path().join("sleep-once"), b"").unwrap();
        let mut cleanup = ContainerCleanup::new(runtime.to_str().unwrap()).unwrap();
        let limits = ProcessLimits {
            timeout: Duration::from_secs(2),
            stdout_bytes: 1024,
            stderr_bytes: 1024,
        };

        assert!(cleanup.remove_with_limits(limits).await.is_err());
        assert!(cleanup.armed);
        drop(cleanup);

        wait_for_call_count(&calls, 2).await;
    }

    #[cfg(unix)]
    #[test]
    fn abrupt_owner_death_force_removes_the_revng_container() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let runtime = root.path().join("fake-runtime");
        let ready = root.path().join("ready");
        let cleaned = root.path().join("cleaned");
        fs::write(
            &runtime,
            "#!/bin/sh\nprintf '%s' \"$3\" > \"$KUZUSHI_REVNG_GUARD_TEST_CLEANED\"\n",
        )
        .unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let mut owner = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("revng_container_cleanup_owner_helper")
            .arg("--nocapture")
            .env(REVNG_GUARD_RUNTIME_ENV, &runtime)
            .env(REVNG_GUARD_READY_ENV, &ready)
            .env(REVNG_GUARD_CLEANED_ENV, &cleaned)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let expected_name = wait_for_file(&ready, Some(&mut owner));

        owner.kill().unwrap();
        owner.wait().unwrap();

        assert_eq!(wait_for_file(&cleaned, None), expected_name);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn revng_container_cleanup_owner_helper() {
        let Some(runtime) = std::env::var_os(REVNG_GUARD_RUNTIME_ENV) else {
            return;
        };
        let ready = PathBuf::from(std::env::var_os(REVNG_GUARD_READY_ENV).unwrap());
        let cleanup = ContainerCleanup::new(runtime.to_str().unwrap()).unwrap();
        fs::write(ready, cleanup.name()).unwrap();
        tokio::time::sleep(Duration::from_secs(60)).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn host_parser_cannot_read_beyond_its_private_input_root() {
        use std::os::unix::fs::PermissionsExt;

        let tools = tempfile::tempdir().unwrap();
        let secrets = tempfile::tempdir().unwrap();
        let input_root = tempfile::tempdir().unwrap();
        let secret = secrets.path().join("secret");
        fs::write(&secret, "HOST_SECRET\n").unwrap();
        let parser = tools.path().join("parser");
        fs::write(&parser, format!("#!/bin/sh\ncat '{}'\n", secret.display())).unwrap();
        fs::set_permissions(&parser, fs::Permissions::from_mode(0o700)).unwrap();
        let input = input_root.path().join("input.bin");
        fs::write(&input, b"ELF").unwrap();

        let error = run_host_tool(parser.to_str().unwrap(), [input.as_os_str()])
            .await
            .unwrap_err();

        assert!(!format!("{error:#}").contains("HOST_SECRET"));
    }

    #[cfg(unix)]
    async fn wait_for_call_count(path: &Path, expected: u64) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline {
            if fs::metadata(path).is_ok_and(|metadata| metadata.len() >= expected) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("cleanup retry was not observed");
    }

    #[cfg(unix)]
    fn wait_for_file(path: &Path, mut owner: Option<&mut std::process::Child>) -> String {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if let Ok(value) = fs::read_to_string(path) {
                return value;
            }
            if let Some(owner) = owner.as_mut() {
                assert!(
                    owner.try_wait().unwrap().is_none(),
                    "rev.ng parent-death fixture exited before writing {}",
                    path.display()
                );
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!(
            "rev.ng parent-death fixture did not write {}",
            path.display()
        );
    }
}

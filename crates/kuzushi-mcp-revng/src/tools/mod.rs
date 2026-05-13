use anyhow::{Context, Result};
use async_trait::async_trait;
use kuzushi_mcp_common::{
    cache::{index_root, sha256_file_hex},
    doctor::which,
    Tool, ToolHandler, ToolRegistry,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;

const DEFAULT_REVNG_IMAGE: &str = "revng/revng:latest";

pub(crate) fn build_registry() -> ToolRegistry {
    ToolRegistry::new()
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
            AnalyzeBinaryTool,
        )
        .register(
            descriptor(
                "revng.list_functions",
                "List functions discovered by rev.ng for the binary.",
                binary_schema(),
            ),
            ListFunctionsTool,
        )
        .register(
            descriptor(
                "revng.decompile_function",
                "Return rev.ng decompilation output for one function.",
                function_schema(),
            ),
            DecompileFunctionTool,
        )
        .register(
            descriptor(
                "revng.function_cfg",
                "Return control-flow facts for one function.",
                function_schema(),
            ),
            FunctionCfgTool,
        )
        .register(
            descriptor(
                "revng.strings",
                "Return printable strings from the binary, cached beside rev.ng outputs.",
                binary_schema(),
            ),
            StringsTool,
        )
        .register(
            descriptor(
                "revng.symbols",
                "Return dynamic/static symbols from the binary when available.",
                binary_schema(),
            ),
            SymbolsTool,
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
        "properties": {
            "binary": {"type": "string"},
            "image": {"type": "string", "description": "Container image to run. Defaults to revng/revng:latest."}
        }
    })
}

fn function_schema() -> Value {
    json!({
        "type": "object",
        "required": ["binary", "function"],
        "properties": {
            "binary": {"type": "string"},
            "function": {"type": "string"},
            "image": {"type": "string"}
        }
    })
}

struct HealthTool;
struct AnalyzeBinaryTool;
struct ListFunctionsTool;
struct DecompileFunctionTool;
struct FunctionCfgTool;
struct StringsTool;
struct SymbolsTool;

#[async_trait]
impl ToolHandler for HealthTool {
    async fn call(&self, _args: Value) -> Result<Value> {
        Ok(serde_json::to_value(health_summary().await)?)
    }
}

#[async_trait]
impl ToolHandler for AnalyzeBinaryTool {
    async fn call(&self, args: Value) -> Result<Value> {
        run_revng_cached(&args, RevngAction::Analyze).await
    }
}

#[async_trait]
impl ToolHandler for ListFunctionsTool {
    async fn call(&self, args: Value) -> Result<Value> {
        run_revng_cached(&args, RevngAction::ListFunctions).await
    }
}

#[async_trait]
impl ToolHandler for DecompileFunctionTool {
    async fn call(&self, args: Value) -> Result<Value> {
        run_revng_cached(&args, RevngAction::Decompile).await
    }
}

#[async_trait]
impl ToolHandler for FunctionCfgTool {
    async fn call(&self, args: Value) -> Result<Value> {
        run_revng_cached(&args, RevngAction::Cfg).await
    }
}

#[async_trait]
impl ToolHandler for StringsTool {
    async fn call(&self, args: Value) -> Result<Value> {
        let binary = required_path(&args, "binary")?;
        let output = run_host_tool("strings", [&binary]).await?;
        Ok(
            json!({"binary": binary.display().to_string(), "strings": output.lines().take(500).collect::<Vec<_>>() }),
        )
    }
}

#[async_trait]
impl ToolHandler for SymbolsTool {
    async fn call(&self, args: Value) -> Result<Value> {
        let binary = required_path(&args, "binary")?;
        let output = match run_host_tool("nm", [binary.as_os_str()]).await {
            Ok(output) => output,
            Err(_) => run_host_tool("readelf", [OsStr::new("-Ws"), binary.as_os_str()]).await?,
        };
        Ok(
            json!({"binary": binary.display().to_string(), "symbols": output.lines().take(1000).collect::<Vec<_>>() }),
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
    let runtime = container_runtime();
    let image = revng_image(None);
    let cache_path = revng_cache_root()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "<unavailable>".to_string());
    let image_available = match runtime.as_deref() {
        Some(runtime) => image_exists(runtime, &image).await,
        None => false,
    };
    let mut missing = Vec::new();
    let mode = if native.is_some() {
        Some("native".to_string())
    } else if runtime.is_some() && image_available {
        Some("container".to_string())
    } else {
        None
    };
    if native.is_none() && runtime.is_none() {
        missing.push("native-revng-or-docker-or-podman".to_string());
    }
    if native.is_none() && runtime.is_some() && !image_available {
        missing.push(image.clone());
    }
    let ready = mode.is_some();
    RevngHealth {
        ready,
        mode,
        native_path: native.map(|path| path.display().to_string()),
        runtime,
        image,
        image_available,
        cache_path,
        missing,
    }
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
                    "--analyze".into(),
                    "decompile-to-single-file".into(),
                    binary,
                ]
            }
            Self::Cfg => {
                vec![
                    "revng".into(),
                    "artifact".into(),
                    "--analyze".into(),
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
                vec![
                    "artifact".into(),
                    "--analyze".into(),
                    "decompile-to-single-file".into(),
                    binary,
                ]
            }
            Self::Cfg => {
                vec![
                    "artifact".into(),
                    "--analyze".into(),
                    "render-svg-cfg".into(),
                    binary,
                ]
            }
        }
    }
}

async fn run_revng_cached(args: &Value, action: RevngAction) -> Result<Value> {
    let binary = required_path(args, "binary")?;
    let function = args.get("function").and_then(Value::as_str);
    let backend = select_backend(args.get("image").and_then(Value::as_str)).await?;
    let cache_file = cache_file_for(&binary, &backend.cache_key, action, function)?;
    if cache_file.exists() {
        let output = fs::read_to_string(&cache_file)
            .with_context(|| format!("could not read {}", cache_file.display()))?;
        return Ok(revng_output_json(
            &binary,
            &backend,
            &cache_file,
            true,
            output,
        ));
    }

    if let Some(parent) = cache_file.parent() {
        fs::create_dir_all(parent)?;
    }
    let raw_output = match &backend.kind {
        RevngBackendKind::Native(path) => run_revng_native(path, &binary, action, function).await?,
        RevngBackendKind::Container { runtime, image } => {
            run_revng_container(runtime, image, &binary, action, function).await?
        }
    };
    let output = function
        .map(|name| extract_revng_function_excerpt(&raw_output, name))
        .unwrap_or(raw_output);
    fs::write(&cache_file, &output)
        .with_context(|| format!("could not write {}", cache_file.display()))?;
    Ok(revng_output_json(
        &binary,
        &backend,
        &cache_file,
        false,
        output,
    ))
}

fn revng_output_json(
    binary: &Path,
    backend: &RevngBackend,
    cache_file: &Path,
    cached: bool,
    output: String,
) -> Value {
    json!({
        "binary": binary.display().to_string(),
        "backend": backend.label,
        "cached": cached,
        "cacheFile": cache_file.display().to_string(),
        "output": output,
    })
}

struct RevngBackend {
    kind: RevngBackendKind,
    label: String,
    cache_key: String,
}

enum RevngBackendKind {
    Native(PathBuf),
    Container { runtime: String, image: String },
}

async fn select_backend(image_override: Option<&str>) -> Result<RevngBackend> {
    if let Some(path) = native_revng() {
        let version = revng_version(&path)
            .await
            .unwrap_or_else(|| "unknown-version".to_string());
        return Ok(RevngBackend {
            label: format!("native:{}", path.display()),
            cache_key: format!("native:{version}"),
            kind: RevngBackendKind::Native(path),
        });
    }
    let image = revng_image(image_override);
    let runtime = container_runtime().context(
        "rev.ng MCP requires native revng, Docker, or Podman. Install native revng, or set KUZUSHI_REVNG_NATIVE/KUZUSHI_REVNG_CONTAINER_RUNTIME.",
    )?;
    Ok(RevngBackend {
        label: format!("container:{runtime}:{image}"),
        cache_key: format!("container:{image}"),
        kind: RevngBackendKind::Container { runtime, image },
    })
}

async fn run_revng_native(
    revng: &Path,
    binary: &Path,
    action: RevngAction,
    _function: Option<&str>,
) -> Result<String> {
    let output = Command::new(revng)
        .args(action.native_args(binary))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .with_context(|| format!("could not invoke native rev.ng at {}", revng.display()))?;
    if !output.status.success() {
        anyhow::bail!(
            "native rev.ng exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

async fn run_revng_container(
    runtime: &str,
    image: &str,
    binary: &Path,
    action: RevngAction,
    _function: Option<&str>,
) -> Result<String> {
    let binary_dir = binary
        .parent()
        .context("binary path has no parent directory")?;
    let binary_name = binary
        .file_name()
        .and_then(OsStr::to_str)
        .context("binary file name is not valid UTF-8")?;
    let volume = format!("{}:/input:ro", binary_dir.display());
    let mut command = Command::new(runtime);
    command
        .arg("run")
        .arg("--rm")
        .arg("--pull=never")
        .arg("-v")
        .arg(volume)
        .arg(image)
        .args(action.container_args(binary_name))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = command
        .output()
        .await
        .with_context(|| format!("could not invoke container runtime `{runtime}`"))?;
    if !output.status.success() {
        anyhow::bail!(
            "rev.ng container exited with {}: {}",
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
            strip_ptml_excerpt(output, 24_000)
        );
    };
    let start = output[..name_at]
        .rfind("<div data-scope=\"c.function\"")
        .unwrap_or_else(|| name_at.saturating_sub(12_000));
    let end = output[name_at..]
        .find("<div data-scope=\"c.function\"")
        .map(|offset| name_at + offset)
        .unwrap_or_else(|| (name_at + 24_000).min(output.len()));
    strip_ptml_excerpt(&output[start..end.min(output.len())], 24_000)
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

fn required_path(args: &Value, name: &str) -> Result<PathBuf> {
    let raw = args
        .get(name)
        .and_then(Value::as_str)
        .with_context(|| format!("missing required {name}"))?;
    let path = PathBuf::from(raw);
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    let canonical = fs::canonicalize(&path)
        .with_context(|| format!("{name} does not exist: {}", path.display()))?;
    if !canonical.is_file() {
        anyhow::bail!("{name} must be a file: {}", canonical.display());
    }
    Ok(canonical)
}

fn revng_image(value: Option<&str>) -> String {
    value
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .or_else(|| std::env::var("KUZUSHI_REVNG_IMAGE").ok())
        .unwrap_or_else(|| DEFAULT_REVNG_IMAGE.to_string())
}

fn native_revng() -> Option<PathBuf> {
    if let Ok(value) = std::env::var("KUZUSHI_REVNG_NATIVE") {
        let path = PathBuf::from(value.trim());
        if path.is_file() {
            return Some(path);
        }
    }
    if which("revng").is_some() {
        return Some(PathBuf::from("revng"));
    }
    if let Ok(home) = std::env::var("HOME") {
        let installed = PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("kuzushi")
            .join("revng")
            .join("revng");
        if installed.is_file() {
            return Some(installed);
        }
    }
    let local = std::env::current_dir().ok()?.join("revng").join("revng");
    local.is_file().then_some(local)
}

async fn revng_version(path: &Path) -> Option<String> {
    let output = Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .ok()?;
    let bytes = if output.stdout.is_empty() {
        output.stderr
    } else {
        output.stdout
    };
    let version = String::from_utf8_lossy(&bytes).trim().to_string();
    (!version.is_empty()).then_some(version)
}

fn container_runtime() -> Option<String> {
    if let Ok(value) = std::env::var("KUZUSHI_REVNG_CONTAINER_RUNTIME") {
        if !value.trim().is_empty() {
            return Some(value);
        }
    }
    ["podman", "docker"]
        .iter()
        .find(|binary| container_runtime_is_usable(binary))
        .map(|binary| (*binary).to_string())
}

fn container_runtime_is_usable(binary: &str) -> bool {
    if which(binary).is_none() {
        return false;
    }
    std::process::Command::new(binary)
        .arg("info")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

async fn image_exists(runtime: &str, image: &str) -> bool {
    Command::new(runtime)
        .arg("image")
        .arg("inspect")
        .arg(image)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|status| status.success())
        .unwrap_or(false)
}

fn revng_cache_root() -> Result<PathBuf> {
    Ok(index_root()?.join("revng"))
}

fn cache_file_for(
    binary: &Path,
    image: &str,
    action: RevngAction,
    function: Option<&str>,
) -> Result<PathBuf> {
    let binary_hash = file_hash(binary)?;
    let image_key = stable_key(image);
    let function_key = function
        .map(stable_key)
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
    let output = Command::new(binary)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .with_context(|| format!("could not invoke `{binary}`"))?;
    if !output.status.success() {
        anyhow::bail!("`{binary}` exited with {}", output.status);
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn file_hash(path: &Path) -> Result<String> {
    sha256_file_hex(path).with_context(|| format!("could not hash {}", path.display()))
}

fn stable_key(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_exposes_revng_tools() {
        let registry = build_registry();
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
    async fn health_reports_missing_runtime_without_panicking() {
        let health = health_summary().await;
        assert!(!health.cache_path.is_empty());
    }
}

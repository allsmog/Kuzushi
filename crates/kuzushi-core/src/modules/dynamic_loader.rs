use super::*;
use crate::modules::registry::DynamicToolBinding;
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

mod runtime_protocol;
use self::runtime_protocol::run_dynamic_host_with_runtime;

#[derive(Debug, Clone, Default)]
pub struct DynamicModuleLoadOptions {
    pub allow_untrusted: bool,
    pub trusted_specifiers: Vec<String>,
}

impl ModuleRegistry {
    pub fn load_dynamic_module(
        &mut self,
        specifier: &str,
        options: &DynamicModuleLoadOptions,
    ) -> Result<()> {
        ensure_dynamic_module_trusted(specifier, options)?;
        let loaded = describe_dynamic_module(specifier)?;
        validate_dynamic_module_shape(&loaded)?;
        let module_id = loaded.module.id.clone();
        let dynamic_module = module(
            &loaded.module.id,
            &loaded.module.name,
            loaded.module.kind,
            &loaded.module.description,
            loaded.tools.clone(),
            Vec::new(),
            false,
        );
        for tool in &loaded.tools {
            self.tools.insert(tool.name.clone(), tool.clone());
            self.executors
                .insert(tool.name.clone(), execute_dynamic_tool);
            self.dynamic_tools.insert(
                tool.name.clone(),
                DynamicToolBinding {
                    specifier: specifier.to_string(),
                    module_id: module_id.clone(),
                },
            );
        }
        self.modules.insert(module_id, dynamic_module);
        Ok(())
    }
}

pub(in crate::modules) fn execute_dynamic_tool(
    registry: &ModuleRegistry,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let binding = registry
        .dynamic_tools
        .get(name)
        .with_context(|| format!("dynamic tool {name:?} is missing host binding"))?;
    let descriptor = registry
        .resolve_tool(name)
        .with_context(|| format!("dynamic tool {name:?} is missing descriptor"))?;
    if descriptor.runtime_requirement == RuntimeRequirement::Always && runtime.is_none() {
        anyhow::bail!(
            "{name} requires an agent runtime; configure a model/runtime before running it"
        );
    }
    if descriptor.runtime_requirement == RuntimeRequirement::Always {
        return execute_dynamic_module_tool_with_runtime(
            &binding.specifier,
            name,
            input,
            ctx,
            runtime.context("dynamic runtime was required but unavailable")?,
        );
    }
    execute_dynamic_module_tool(&binding.specifier, name, input, ctx)
}

#[derive(Debug, Deserialize)]
struct DynamicModuleDescription {
    module: ModuleMetadata,
    tools: Vec<ToolDescriptor>,
}

fn ensure_dynamic_module_trusted(
    specifier: &str,
    options: &DynamicModuleLoadOptions,
) -> Result<()> {
    if options.allow_untrusted
        || options
            .trusted_specifiers
            .iter()
            .any(|entry| entry == specifier)
    {
        return Ok(());
    }
    anyhow::bail!(
        "dynamic module {specifier:?} is not trusted. Add it to operator.trusted_modules in $HOME/.kuzushi/v2/config.toml or pass --allow-untrusted-module for this run."
    )
}

fn describe_dynamic_module(specifier: &str) -> Result<DynamicModuleDescription> {
    let output = run_dynamic_host(["describe", specifier], None)?;
    serde_json::from_slice(&output)
        .with_context(|| format!("dynamic module {specifier:?} returned invalid descriptor JSON"))
}

fn execute_dynamic_module_tool(
    specifier: &str,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let context = json!({
        "cwd": ctx.configured_cwd_for_dynamic_tool(),
        "config": ctx.config,
    });
    let payload = json!({
        "input": input,
        "context": context,
    });
    let output = run_dynamic_host(
        ["execute", specifier, name],
        Some(serde_json::to_vec(&payload)?),
    )?;
    serde_json::from_slice(&output)
        .with_context(|| format!("dynamic tool {name:?} returned invalid JSON"))
}

fn execute_dynamic_module_tool_with_runtime(
    specifier: &str,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: &dyn AgentRuntime,
) -> Result<Value> {
    let payload = json!({
        "input": input,
        "context": dynamic_tool_context_json(ctx),
    });
    run_dynamic_host_with_runtime(specifier, name, payload, runtime)
}

trait DynamicToolContext {
    fn configured_cwd_for_dynamic_tool(&self) -> String;
}

impl DynamicToolContext for ToolExecutionContext<'_> {
    fn configured_cwd_for_dynamic_tool(&self) -> String {
        self.workspace
            .map(|workspace| workspace.root().display().to_string())
            .unwrap_or_else(|| {
                std::env::current_dir()
                    .map_or_else(|_| ".".to_string(), |path| path.display().to_string())
            })
    }
}

fn validate_dynamic_module_shape(loaded: &DynamicModuleDescription) -> Result<()> {
    if loaded.module.id.trim().is_empty() {
        anyhow::bail!("dynamic module id must not be empty");
    }
    for tool in &loaded.tools {
        let Some((prefix, _)) = tool.name.split_once(':') else {
            anyhow::bail!("dynamic tool {:?} must use <moduleId>:<action>", tool.name);
        };
        if prefix != loaded.module.id {
            anyhow::bail!(
                "dynamic tool {:?} must start with module id {:?}",
                tool.name,
                loaded.module.id
            );
        }
    }
    Ok(())
}

fn dynamic_tool_context_json(ctx: &ToolExecutionContext<'_>) -> Value {
    json!({
        "cwd": ctx.configured_cwd_for_dynamic_tool(),
        "config": ctx.config,
    })
}

fn run_dynamic_host<const N: usize>(args: [&str; N], stdin: Option<Vec<u8>>) -> Result<Vec<u8>> {
    let mut command = dynamic_host_command(args)?;
    if stdin.is_some() {
        command.stdin(std::process::Stdio::piped());
    }
    let mut child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("could not start node dynamic module host")?;
    if let Some(stdin) = stdin {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .context("dynamic module host stdin was unavailable")?
            .write_all(&stdin)
            .context("could not write dynamic module host request")?;
    }
    let output = child
        .wait_with_output()
        .context("could not read dynamic module host output")?;
    if !output.status.success() {
        anyhow::bail!(
            "dynamic module host failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

pub(super) fn dynamic_host_command<const N: usize>(args: [&str; N]) -> Result<Command> {
    let mut command = Command::new("node");
    command.arg(dynamic_host_script()?);
    command.args(args);
    Ok(command)
}

fn dynamic_host_script() -> Result<PathBuf> {
    if let Some(path) = configured_dynamic_host_script()? {
        return Ok(path);
    }
    if let Some(path) = dynamic_host_script_in_source_checkout() {
        return Ok(path);
    }
    if let Some(path) = dynamic_host_script_near_current_exe() {
        return Ok(path);
    }
    anyhow::bail!(
        "could not locate scripts/kuzushi-dynamic-module-host.mjs. Set KUZUSHI_DYNAMIC_MODULE_HOST to the host script path."
    )
}

fn configured_dynamic_host_script() -> Result<Option<PathBuf>> {
    let Some(path) = std::env::var_os("KUZUSHI_DYNAMIC_MODULE_HOST") else {
        return Ok(None);
    };
    let path = PathBuf::from(path);
    if path.is_file() {
        return Ok(Some(path));
    }
    anyhow::bail!(
        "KUZUSHI_DYNAMIC_MODULE_HOST points to a missing dynamic module host script: {}",
        path.display()
    )
}

fn dynamic_host_script_in_source_checkout() -> Option<PathBuf> {
    let core_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    core_dir
        .parent()
        .and_then(Path::parent)
        .map(|root| root.join("scripts").join("kuzushi-dynamic-module-host.mjs"))
        .filter(|script| script.is_file())
}

fn dynamic_host_script_near_current_exe() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    dynamic_host_script_candidates_above(exe.parent()?.to_path_buf())
        .into_iter()
        .find(|script| script.is_file())
}

fn dynamic_host_script_candidates_above(mut dir: PathBuf) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    for _ in 0..6 {
        candidates.push(dir.join("scripts").join("kuzushi-dynamic-module-host.mjs"));
        if !dir.pop() {
            break;
        }
    }
    candidates
}

#[cfg(test)]
mod dynamic_loader_tests {
    use super::*;
    use std::fs;

    #[test]
    fn dynamic_host_candidates_cover_native_package_layout() {
        let package = tempfile::tempdir().unwrap();
        let native_dir = package.path().join("native").join("darwin-arm64");
        let script = package
            .path()
            .join("scripts")
            .join("kuzushi-dynamic-module-host.mjs");
        fs::create_dir_all(&native_dir).unwrap();
        fs::create_dir_all(script.parent().unwrap()).unwrap();
        fs::write(&script, "host").unwrap();

        let candidates = dynamic_host_script_candidates_above(native_dir);

        assert!(candidates.contains(&script));
    }
}

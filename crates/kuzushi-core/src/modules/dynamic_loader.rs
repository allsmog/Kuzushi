use super::*;
use crate::modules::registry::DynamicToolBinding;
use crate::worker_protocol::{
    descriptor_hash_from_value, resolve_file_worker_bundle, run_node_worker_tool_blocking,
    ConfiguredSignatureVerifier, ExecutorTier, Grant, KuzushiLockfile, LockfileEntry,
    NodeWorkerRun, ResolvedWorkerBundle, VerifiedModule,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

mod runtime_protocol;
use self::runtime_protocol::run_dynamic_host_with_runtime;

#[derive(Debug, Clone, Default)]
pub struct DynamicModuleLoadOptions {
    pub lockfile_path: Option<PathBuf>,
}

impl ModuleRegistry {
    pub fn load_dynamic_module(
        &mut self,
        specifier: &str,
        options: &DynamicModuleLoadOptions,
    ) -> Result<()> {
        let verified = verify_dynamic_module_before_describe(specifier, options)?;
        let loaded = describe_dynamic_module(specifier)?;
        validate_dynamic_module_shape(&loaded)?;
        verify_loaded_descriptor(&verified, &loaded)?;
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
                    verified: Some(verified.clone()),
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
    if let Some(verified) = binding.verified.as_ref() {
        return execute_dynamic_module_tool_with_worker(
            binding,
            verified,
            name,
            input,
            ctx,
            runtime,
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

#[derive(Debug, Serialize, Deserialize)]
struct DynamicModuleDescription {
    module: ModuleMetadata,
    tools: Vec<ToolDescriptor>,
}

fn verify_dynamic_module_before_describe(
    specifier: &str,
    options: &DynamicModuleLoadOptions,
) -> Result<VerifiedModule> {
    let resolved = resolve_file_worker_bundle(specifier)?;
    let lockfile_path = dynamic_lockfile_path(options);
    let lockfile = KuzushiLockfile::read_json(&lockfile_path).with_context(|| {
        format!(
            "dynamic module {specifier:?} is not approved; run `kuzushi kwp approve {specifier}` to write {}",
            lockfile_path.display()
        )
    })?;
    let entry = lockfile
        .entry_for_digest(&resolved.digest)
        .with_context(|| format!("dynamic module digest {} is not approved in {}", resolved.digest.0, lockfile_path.display()))?;
    if entry.revoked {
        anyhow::bail!("dynamic module digest {} has been revoked in {}", resolved.digest.0, lockfile_path.display());
    }
    ensure_signature_chain_verified(entry)?;
    Ok(VerifiedModule {
        module_id: entry.module_id.clone(),
        digest: resolved.digest,
        descriptor_hash: entry.descriptor_hash.clone(),
        module_root: resolved.module_root,
        entry: resolved.entry,
        tier: resolved.tier,
        grant: Arc::new(entry.grant.clone()),
    })
}

fn ensure_signature_chain_verified(entry: &LockfileEntry) -> Result<()> {
    if entry.signature_chain.is_empty() {
        return Ok(());
    }
    let config = crate::config::load_config_for_target(None)
        .context("could not load operator signature trust config")?;
    ConfiguredSignatureVerifier::new(config.operator.signature_keys)
        .verify_lockfile_entry(entry)
        .with_context(|| {
            format!(
                "dynamic module digest {} has an unverifiable signatureChain",
                entry.digest.0
            )
        })
}

fn verify_loaded_descriptor(verified: &VerifiedModule, loaded: &DynamicModuleDescription) -> Result<()> {
    if verified.module_id.0 != loaded.module.id {
        anyhow::bail!(
            "dynamic module id changed after approval: lockfile has {:?}, loaded descriptor has {:?}",
            verified.module_id.0,
            loaded.module.id
        );
    }
    let descriptor_value = serde_json::to_value(loaded)?;
    let descriptor_hash = descriptor_hash_from_value(&descriptor_value)?;
    if verified.descriptor_hash != descriptor_hash {
        anyhow::bail!(
            "dynamic module descriptor hash changed after approval: lockfile has {}, loaded descriptor has {}",
            verified.descriptor_hash,
            descriptor_hash
        );
    }
    Ok(())
}

fn dynamic_lockfile_path(options: &DynamicModuleLoadOptions) -> PathBuf {
    options
        .lockfile_path
        .clone()
        .unwrap_or_else(default_dynamic_lockfile_path)
}

pub fn default_dynamic_lockfile_path() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("kuzushi.lock")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DynamicModuleInspection {
    pub specifier: String,
    pub digest: String,
    pub module_id: Option<String>,
    pub descriptor_hash: Option<String>,
    pub approved: bool,
    pub revoked: bool,
    pub lockfile_path: String,
}

pub fn approve_dynamic_module(
    specifier: &str,
    grant: Grant,
    version: &str,
    lockfile_path: &Path,
) -> Result<LockfileEntry> {
    let resolved = resolve_file_worker_bundle(specifier)?;
    let loaded = describe_dynamic_module(specifier)?;
    validate_dynamic_module_shape(&loaded)?;
    let descriptor_hash = descriptor_hash_from_value(&serde_json::to_value(&loaded)?)?;
    let entry = LockfileEntry {
        module_id: crate::worker_protocol::ModuleId(loaded.module.id),
        digest: resolved.digest,
        version: version.to_string(),
        descriptor_hash,
        grant,
        signature_chain: Vec::new(),
        revoked: false,
    };
    let mut lockfile = KuzushiLockfile::read_json_or_default(lockfile_path)?;
    lockfile.approve(entry.clone())?;
    lockfile.write_json(lockfile_path)?;
    Ok(entry)
}

pub fn revoke_dynamic_module(digest: &str, lockfile_path: &Path) -> Result<LockfileEntry> {
    let mut lockfile = KuzushiLockfile::read_json(lockfile_path)?;
    let entry = lockfile
        .modules
        .get_mut(digest)
        .with_context(|| format!("digest {digest:?} is not present in {}", lockfile_path.display()))?;
    entry.revoked = true;
    let revoked = entry.clone();
    lockfile.write_json(lockfile_path)?;
    Ok(revoked)
}

pub fn inspect_dynamic_module(specifier: &str, lockfile_path: &Path) -> Result<DynamicModuleInspection> {
    let resolved = resolve_file_worker_bundle(specifier)?;
    let lockfile = KuzushiLockfile::read_json_or_default(lockfile_path)?;
    let entry = lockfile.entry_for_digest(&resolved.digest);
    Ok(DynamicModuleInspection {
        specifier: specifier.to_string(),
        digest: resolved.digest.0,
        module_id: entry.map(|entry| entry.module_id.0.clone()),
        descriptor_hash: entry.map(|entry| entry.descriptor_hash.clone()),
        approved: entry.is_some(),
        revoked: entry.is_some_and(|entry| entry.revoked),
        lockfile_path: lockfile_path.display().to_string(),
    })
}

fn describe_dynamic_module(specifier: &str) -> Result<DynamicModuleDescription> {
    let resolved = resolve_file_worker_bundle(specifier)?;
    let import_path = resolved_worker_import_path(&resolved);
    let output = run_dynamic_host_with_command(
        sandboxed_dynamic_host_command(["describe", import_path.as_str()], &resolved)?,
        None,
    )?;
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

fn execute_dynamic_module_tool_with_worker(
    binding: &DynamicToolBinding,
    verified: &VerifiedModule,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let command = kwp_worker_command(&binding.specifier, verified)?;
    run_node_worker_tool_blocking(NodeWorkerRun {
        command,
        module: verified,
        tool_name: name,
        input,
        context: ctx,
        runtime,
    })
    .map_err(anyhow::Error::from)
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

fn kwp_worker_command(specifier: &str, verified: &VerifiedModule) -> Result<Command> {
    if verified.tier != ExecutorTier::Node {
        anyhow::bail!("unsupported KWP worker tier {:?}", verified.tier);
    }
    let script = dynamic_host_script()?;
    let mut command = sandboxed_node_command(&script, &verified.module_root);
    command.arg(&script);
    command.arg("serve");
    command.arg(worker_import_path(specifier, verified));
    Ok(command)
}

fn sandboxed_dynamic_host_command<const N: usize>(
    args: [&str; N],
    resolved: &ResolvedWorkerBundle,
) -> Result<Command> {
    if resolved.tier != ExecutorTier::Node {
        anyhow::bail!("unsupported KWP worker tier {:?}", resolved.tier);
    }
    let script = dynamic_host_script()?;
    let mut command = sandboxed_node_command(&script, &resolved.module_root);
    command.arg(&script);
    command.args(args);
    Ok(command)
}

fn sandboxed_node_command(script: &Path, module_root: &Path) -> Command {
    let mut command = Command::new("node");
    command.arg("--permission");
    command.arg(format!("--allow-fs-read={}", script.display()));
    if let Some(parent) = script.parent() {
        command.arg(format!("--allow-fs-read={}", parent.display()));
    }
    command.arg(format!("--allow-fs-read={}", module_root.display()));
    sanitize_worker_environment(&mut command);
    command
}

fn worker_import_path(specifier: &str, verified: &VerifiedModule) -> String {
    if verified.entry == "." {
        return verified.module_root.display().to_string();
    }
    if specifier.starts_with("file://") {
        return verified.module_root.join(&verified.entry).display().to_string();
    }
    specifier.to_string()
}

fn resolved_worker_import_path(resolved: &ResolvedWorkerBundle) -> String {
    if resolved.entry == "." {
        resolved.module_root.display().to_string()
    } else {
        resolved.module_root.join(&resolved.entry).display().to_string()
    }
}

fn sanitize_worker_environment(command: &mut Command) {
    let path = std::env::var_os("PATH");
    let tmpdir = std::env::var_os("TMPDIR");
    let temp = std::env::var_os("TEMP");
    let tmp = std::env::var_os("TMP");
    command.env_clear();
    if let Some(path) = path {
        command.env("PATH", path);
    }
    if let Some(tmpdir) = tmpdir {
        command.env("TMPDIR", tmpdir);
    }
    if let Some(temp) = temp {
        command.env("TEMP", temp);
    }
    if let Some(tmp) = tmp {
        command.env("TMP", tmp);
    }
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
    run_dynamic_host_with_command(dynamic_host_command(args)?, stdin)
}

fn run_dynamic_host_with_command(mut command: Command, stdin: Option<Vec<u8>>) -> Result<Vec<u8>> {
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
        let _ = child.stdin.take();
    }
    let output = wait_for_dynamic_host_output(child, Duration::from_secs(30))?;
    if !output.status.success() {
        anyhow::bail!(
            "dynamic module host failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

fn wait_for_dynamic_host_output(
    mut child: std::process::Child,
    timeout: Duration,
) -> Result<std::process::Output> {
    let deadline = Instant::now() + timeout;
    loop {
        if child
            .try_wait()
            .context("could not poll dynamic module host")?
            .is_some()
        {
            return child
                .wait_with_output()
                .context("could not read dynamic module host output");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child
                .wait_with_output()
                .context("could not read timed-out dynamic module host output")?;
            anyhow::bail!(
                "dynamic module host timed out after {}ms: {}",
                timeout.as_millis(),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
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

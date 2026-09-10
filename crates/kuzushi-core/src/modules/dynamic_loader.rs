use super::*;
use crate::modules::registry::DynamicToolBinding;
use crate::worker_protocol::{
    descriptor_hash_from_value, resolve_file_worker_bundle, run_node_worker_tool_blocking,
    ConfiguredSignatureVerifier, ExecutorTier, FsScope, Grant, KuzushiLockfile, LockfileEntry,
    NodeWorkerRun, ResolvedWorkerBundle, TrustError, VerifiedModule,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

mod runtime_protocol;
use self::runtime_protocol::run_dynamic_host_with_runtime;

pub(super) const DYNAMIC_HOST_PROTOCOL_VERSION: u64 = 1;
pub(super) const DYNAMIC_HOST_SDK_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Default)]
pub struct DynamicModuleLoadOptions {
    /// Legacy trust allowlist for non-local compatibility specifiers.
    pub trusted_specifiers: Vec<String>,
    /// Content-addressed approval store for local file/path workers.
    pub lockfile_path: Option<PathBuf>,
}

impl ModuleRegistry {
    pub fn load_dynamic_module(
        &mut self,
        specifier: &str,
        options: &DynamicModuleLoadOptions,
    ) -> Result<()> {
        let verified_worker = verify_dynamic_module_before_describe(specifier, options)?;
        let mut loaded = match verified_worker.as_ref() {
            Some(worker) => describe_verified_worker(worker)?,
            None => describe_dynamic_module(specifier)?,
        };
        validate_dynamic_module_shape(&mut loaded)?;
        if let Some(worker) = verified_worker.as_ref() {
            verify_loaded_descriptor(&worker.module, &loaded)?;
        }
        self.ensure_dynamic_module_slots_are_available(&loaded)?;
        self.install_dynamic_module(specifier, loaded, verified_worker.as_ref());
        Ok(())
    }

    fn install_dynamic_module(
        &mut self,
        specifier: &str,
        loaded: DynamicModuleDescription,
        worker: Option<&VerifiedDynamicWorker>,
    ) {
        let module_id = loaded.module.id.clone();
        let dynamic_module = module(
            &loaded.module.id,
            &loaded.module.name,
            loaded.module.kind,
            &loaded.module.description,
            loaded.tools.clone(),
            Vec::new(),
            loaded.hidden,
        );
        for tool in &loaded.tools {
            self.tools.insert(tool.name.clone(), tool.clone());
            self.executors
                .insert(tool.name.clone(), execute_dynamic_tool);
            self.dynamic_tools.insert(
                tool.name.clone(),
                dynamic_tool_binding(specifier, &module_id, worker),
            );
        }
        self.modules.insert(module_id, dynamic_module);
    }

    fn ensure_dynamic_module_slots_are_available(
        &self,
        loaded: &DynamicModuleDescription,
    ) -> Result<()> {
        if self.modules.contains_key(&loaded.module.id)
            || retired_builtin_module_id(&loaded.module.id)
        {
            anyhow::bail!(
                "dynamic module id {:?} collides with an active or retired built-in module",
                loaded.module.id
            );
        }
        for tool in &loaded.tools {
            if self.tools.contains_key(&tool.name) {
                anyhow::bail!(
                    "dynamic tool {:?} collides with an already registered tool",
                    tool.name
                );
            }
        }
        Ok(())
    }
}

fn retired_builtin_module_id(id: &str) -> bool {
    matches!(
        id,
        "bounty"
            | "catalog"
            | "carlini-threat-hunt"
            | "chrome-rce"
            | "classifier-gate"
            | "context-lite"
            | "deep-audit"
            | "exploit-chain"
            | "full-mode"
            | "module-recommender"
            | "offense"
            | "pipeline"
            | "prompt-armor"
            | "pwn"
            | "randori"
            | "shinsa"
            | "smoke"
            | "taint-iris"
            | "threat-leads"
            | "tob"
            | "uaf-hunt"
            | "vendor-assessment"
            | "vuln-scout"
    )
}

fn dynamic_tool_binding(
    specifier: &str,
    module_id: &str,
    worker: Option<&VerifiedDynamicWorker>,
) -> DynamicToolBinding {
    DynamicToolBinding {
        specifier: specifier.to_string(),
        module_id: module_id.to_string(),
        verified: worker.map(|worker| worker.module.clone()),
        lockfile_path: worker.map(|worker| worker.lockfile_path.clone()),
        approval: worker.map(|worker| worker.approval.clone()),
        _bundle_snapshot: worker.map(|worker| Arc::clone(&worker.snapshot)),
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
            binding, verified, name, input, ctx, runtime,
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
    #[serde(default)]
    hidden: bool,
    tools: Vec<ToolDescriptor>,
}

fn verify_dynamic_module_before_describe(
    specifier: &str,
    options: &DynamicModuleLoadOptions,
) -> Result<Option<VerifiedDynamicWorker>> {
    match resolve_file_worker_bundle(specifier) {
        Ok(resolved) => verify_resolved_worker(&resolved, options).map(Some),
        Err(TrustError::UnsupportedSpecifier(_)) => {
            ensure_dynamic_module_trusted(specifier, options)?;
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

#[derive(Debug)]
struct VerifiedDynamicWorker {
    module: VerifiedModule,
    lockfile_path: PathBuf,
    approval: LockfileEntry,
    snapshot: Arc<tempfile::TempDir>,
}

fn verify_resolved_worker(
    resolved: &ResolvedWorkerBundle,
    options: &DynamicModuleLoadOptions,
) -> Result<VerifiedDynamicWorker> {
    ensure_single_file_worker(resolved)?;
    let (lockfile_path, approval) = approved_lockfile_entry(resolved, options)?;
    ensure_signature_chain_verified(&approval)?;
    let (snapshot, staged) = snapshot_worker_bundle(resolved)?;
    Ok(VerifiedDynamicWorker {
        module: verified_module_from_snapshot(resolved, staged, &approval),
        lockfile_path,
        approval,
        snapshot,
    })
}

fn approved_lockfile_entry(
    resolved: &ResolvedWorkerBundle,
    options: &DynamicModuleLoadOptions,
) -> Result<(PathBuf, LockfileEntry)> {
    let lockfile_path = dynamic_lockfile_path(options)?;
    let lockfile = KuzushiLockfile::read_json(&lockfile_path).with_context(|| {
        format!(
            "dynamic module {:?} is not approved; run `kuzushi kwp approve {}` to write {}",
            resolved.specifier,
            resolved.specifier,
            lockfile_path.display()
        )
    })?;
    let approval = lockfile
        .entry_for_digest(&resolved.digest)
        .with_context(|| {
            format!(
                "dynamic module digest {} is not approved in {}",
                resolved.digest.0,
                lockfile_path.display()
            )
        })?
        .clone();
    if approval.revoked {
        anyhow::bail!(
            "dynamic module digest {} has been revoked in {}",
            resolved.digest.0,
            lockfile_path.display()
        );
    }
    Ok((lockfile_path, approval))
}

fn verified_module_from_snapshot(
    resolved: &ResolvedWorkerBundle,
    staged: ResolvedWorkerBundle,
    approval: &LockfileEntry,
) -> VerifiedModule {
    VerifiedModule {
        module_id: approval.module_id.clone(),
        digest: resolved.digest.clone(),
        descriptor_hash: approval.descriptor_hash.clone(),
        module_root: staged.module_root,
        entry: staged.entry,
        tier: staged.tier,
        grant: Arc::new(approval.grant.clone()),
    }
}

fn ensure_single_file_worker(resolved: &ResolvedWorkerBundle) -> Result<()> {
    if resolved.entry == "." {
        anyhow::bail!(
            "KWP directory bundles are not supported yet; approve one self-contained module entry file"
        );
    }
    Ok(())
}

fn snapshot_worker_bundle(
    resolved: &ResolvedWorkerBundle,
) -> Result<(Arc<tempfile::TempDir>, ResolvedWorkerBundle)> {
    ensure_single_file_worker(resolved)?;
    let snapshot = Arc::new(tempfile::tempdir().context("could not create KWP bundle snapshot")?);
    let source = resolved.module_root.join(&resolved.entry);
    let staged_path = snapshot.path().join(&resolved.entry);
    fs::copy(&source, &staged_path).with_context(|| {
        format!(
            "could not snapshot approved KWP worker {}",
            source.display()
        )
    })?;
    make_snapshot_read_only(&staged_path)?;
    let staged = resolve_file_worker_bundle(&staged_path.display().to_string())?;
    if staged.digest != resolved.digest {
        anyhow::bail!("KWP worker changed while it was being verified; retry the approval or load");
    }
    Ok((snapshot, staged))
}

fn make_snapshot_read_only(path: &Path) -> Result<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions)
        .with_context(|| format!("could not protect KWP snapshot {}", path.display()))
}

fn describe_verified_worker(worker: &VerifiedDynamicWorker) -> Result<DynamicModuleDescription> {
    ensure_verified_snapshot_is_current(&worker.module)?;
    let resolved = ResolvedWorkerBundle {
        specifier: worker.module.module_root.display().to_string(),
        module_root: worker.module.module_root.clone(),
        entry: worker.module.entry.clone(),
        tier: worker.module.tier,
        digest: worker.module.digest.clone(),
    };
    let output = describe_local_worker(&resolved)?;
    warn_deprecated_dynamic_phases(&output, &resolved.specifier);
    serde_json::from_slice(&output).context("verified KWP worker returned invalid descriptor JSON")
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

fn verify_loaded_descriptor(
    verified: &VerifiedModule,
    loaded: &DynamicModuleDescription,
) -> Result<()> {
    if verified.module_id.0 != loaded.module.id {
        anyhow::bail!(
            "dynamic module id changed after approval: lockfile has {:?}, loaded descriptor has {:?}",
            verified.module_id.0,
            loaded.module.id
        );
    }
    let descriptor_hash = descriptor_hash_from_value(&serde_json::to_value(loaded)?)?;
    if verified.descriptor_hash != descriptor_hash {
        anyhow::bail!(
            "dynamic module descriptor hash changed after approval: lockfile has {}, loaded descriptor has {}",
            verified.descriptor_hash,
            descriptor_hash
        );
    }
    Ok(())
}

fn dynamic_lockfile_path(options: &DynamicModuleLoadOptions) -> Result<PathBuf> {
    let path = options
        .lockfile_path
        .clone()
        .unwrap_or_else(default_dynamic_lockfile_path);
    stable_lockfile_path(&path, true)
}

fn stable_lockfile_path(path: &Path, allow_missing: bool) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };
    let absolute = normalize_platform_lockfile_path(&absolute);
    ensure_lockfile_path_has_no_symlinks(&absolute)?;
    if absolute.exists() {
        return fs::canonicalize(&absolute).with_context(|| {
            format!("could not canonicalize KWP lockfile {}", absolute.display())
        });
    }
    if !allow_missing {
        anyhow::bail!("KWP lockfile does not exist: {}", absolute.display());
    }
    let parent = absolute
        .parent()
        .context("KWP lockfile path has no parent directory")?;
    let parent = fs::canonicalize(parent).with_context(|| {
        format!(
            "could not canonicalize KWP lockfile parent {}",
            parent.display()
        )
    })?;
    let name = absolute
        .file_name()
        .context("KWP lockfile path has no file name")?;
    Ok(parent.join(name))
}

fn normalize_platform_lockfile_path(path: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    for (alias, canonical) in [("/var", "/private/var"), ("/tmp", "/private/tmp")] {
        if fs::canonicalize(alias).ok().as_deref() != Some(Path::new(canonical)) {
            continue;
        }
        if let Ok(suffix) = path.strip_prefix(alias) {
            return Path::new(canonical).join(suffix);
        }
    }
    path.to_path_buf()
}

fn ensure_lockfile_path_has_no_symlinks(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            anyhow::bail!(
                "KWP lockfile path must not contain '..': {}",
                path.display()
            );
        }
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                anyhow::bail!(
                    "KWP lockfile path must not contain symlinks: {}",
                    current.display()
                );
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(error).context("could not inspect KWP lockfile path"),
        }
    }
    Ok(())
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
    let lockfile_path = stable_lockfile_path(lockfile_path, true)?;
    let resolved = resolve_file_worker_bundle(specifier)?;
    ensure_single_file_worker(&resolved)?;
    let (_snapshot, staged) = snapshot_worker_bundle(&resolved)?;
    let output = describe_local_worker(&staged)?;
    warn_deprecated_dynamic_phases(&output, specifier);
    let mut loaded: DynamicModuleDescription = serde_json::from_slice(&output)
        .context("KWP worker returned invalid descriptor JSON during approval")?;
    validate_dynamic_module_shape(&mut loaded)?;
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
    let mut lockfile = KuzushiLockfile::read_json_or_default(&lockfile_path)?;
    lockfile.approve(entry.clone())?;
    lockfile.write_json(&lockfile_path)?;
    Ok(entry)
}

pub fn revoke_dynamic_module(digest: &str, lockfile_path: &Path) -> Result<LockfileEntry> {
    let lockfile_path = stable_lockfile_path(lockfile_path, false)?;
    let mut lockfile = KuzushiLockfile::read_json(&lockfile_path)?;
    let entry = lockfile.modules.get_mut(digest).with_context(|| {
        format!(
            "digest {digest:?} is not present in {}",
            lockfile_path.display()
        )
    })?;
    entry.revoked = true;
    let revoked = entry.clone();
    lockfile.write_json(&lockfile_path)?;
    Ok(revoked)
}

pub fn inspect_dynamic_module(
    specifier: &str,
    lockfile_path: &Path,
) -> Result<DynamicModuleInspection> {
    let lockfile_path = stable_lockfile_path(lockfile_path, true)?;
    let resolved = resolve_file_worker_bundle(specifier)?;
    let lockfile = KuzushiLockfile::read_json_or_default(&lockfile_path)?;
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

fn ensure_dynamic_module_trusted(
    specifier: &str,
    options: &DynamicModuleLoadOptions,
) -> Result<()> {
    ensure_package_compatibility_specifier(specifier)?;
    if options
        .trusted_specifiers
        .iter()
        .any(|entry| entry == specifier)
    {
        return Ok(());
    }
    anyhow::bail!(
        "dynamic module {specifier:?} is not trusted. Add it to operator.trusted_modules in $HOME/.kuzushi/v3/config.toml."
    )
}

fn ensure_package_compatibility_specifier(specifier: &str) -> Result<()> {
    let Some(package) = specifier.strip_prefix("package:") else {
        anyhow::bail!(
            "unsupported dynamic module specifier {specifier:?}; use an approved file:// entry or package:<npm-name>"
        );
    };
    if !valid_npm_package_import(package) {
        anyhow::bail!("invalid or local-resolving package specifier {specifier:?}");
    }
    Ok(())
}

fn valid_npm_package_import(package: &str) -> bool {
    if package.is_empty()
        || package.contains(':')
        || package.contains('\\')
        || package.starts_with('.')
        || package.starts_with('/')
    {
        return false;
    }
    let segments = package.split('/').collect::<Vec<_>>();
    let package_segment_count = usize::from(package.starts_with('@')) + 1;
    if segments.len() < package_segment_count {
        return false;
    }
    segments
        .iter()
        .all(|segment| valid_package_path_segment(segment))
}

fn valid_package_path_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'@' | b'-' | b'_' | b'.'))
}

fn describe_dynamic_module(specifier: &str) -> Result<DynamicModuleDescription> {
    let output = match resolve_file_worker_bundle(specifier) {
        Ok(resolved) => describe_local_worker(&resolved)?,
        Err(TrustError::UnsupportedSpecifier(_)) => {
            run_dynamic_host(["describe", specifier], None, None)?
        }
        Err(error) => return Err(error.into()),
    };
    warn_deprecated_dynamic_phases(&output, specifier);
    serde_json::from_slice(&output)
        .with_context(|| format!("dynamic module {specifier:?} returned invalid descriptor JSON"))
}

fn warn_deprecated_dynamic_phases(output: &[u8], specifier: &str) {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(output) else {
        return;
    };
    let Some(tools) = value.get("tools").and_then(serde_json::Value::as_array) else {
        return;
    };
    for tool in tools {
        let Some(phase) = tool.get("phase").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let replacement = match phase {
            "hunt" => "scan",
            "confirm" => "prove",
            _ => continue,
        };
        let name = tool
            .get("name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("<unnamed>");
        crate::runtime_diagnostics::record_runtime_diagnostic(
            "module",
            format!(
                "dynamic module {specifier:?} tool {name:?} uses deprecated phase {phase:?}; use {replacement:?}"
            ),
        );
    }
}

fn describe_local_worker(resolved: &ResolvedWorkerBundle) -> Result<Vec<u8>> {
    let import_path = resolved_worker_import_path(resolved);
    let command = sandboxed_dynamic_host_command(["describe", import_path.as_str()], resolved)?;
    run_dynamic_host_command(command, None, None, DYNAMIC_DESCRIBE_TIMEOUT)
}

fn execute_dynamic_module_tool(
    specifier: &str,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let context = dynamic_tool_context_json(ctx)?;
    let payload = json!({
        "input": input,
        "context": context,
    });
    let output = run_dynamic_host(
        ["execute", specifier, name],
        Some(serde_json::to_vec(&payload)?),
        ctx.cancellation,
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
    ctx.ensure_active()?;
    ensure_verified_approval_is_current(binding, verified, ctx)?;
    ensure_verified_bundle_is_current(&binding.specifier, verified)?;
    ensure_verified_snapshot_is_current(verified)?;
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

fn ensure_verified_approval_is_current(
    binding: &DynamicToolBinding,
    verified: &VerifiedModule,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    let lockfile_path = binding
        .lockfile_path
        .as_ref()
        .context("verified KWP worker is missing its lockfile binding")?;
    ensure_lockfile_is_not_worker_writable(lockfile_path, verified, ctx)?;
    let lockfile = KuzushiLockfile::read_json(lockfile_path)?;
    let entry = lockfile
        .entry_for_digest(&verified.digest)
        .with_context(|| {
            format!(
                "KWP approval {} was removed from {}; reload after approving it again",
                verified.digest.0,
                lockfile_path.display()
            )
        })?;
    if entry.revoked {
        anyhow::bail!(
            "KWP approval {} was revoked in {}; reload after approving it again",
            verified.digest.0,
            lockfile_path.display()
        );
    }
    ensure_signature_chain_verified(entry)?;
    let approved = binding
        .approval
        .as_ref()
        .context("verified KWP worker is missing its approval snapshot")?;
    if entry != approved {
        anyhow::bail!(
            "KWP approval changed in {}; reload the module before executing it",
            lockfile_path.display()
        );
    }
    Ok(())
}

fn ensure_lockfile_is_not_worker_writable(
    lockfile_path: &Path,
    verified: &VerifiedModule,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    let Some(workspace) = ctx.workspace else {
        return Ok(());
    };
    let lockfile = fs::canonicalize(lockfile_path)?;
    ensure_lockfile_is_outside_module_data(&lockfile, verified, workspace)?;
    let workspace_write = verified.grant.allows_fs_write(FsScope::Workspace);
    let input_write = verified.grant.allows_fs_write(FsScope::Input);
    if !workspace_write && !input_write {
        return Ok(());
    }
    let root = fs::canonicalize(workspace.root())?;
    let Ok(relative) = lockfile.strip_prefix(&root) else {
        return Ok(());
    };
    if input_write {
        anyhow::bail!(
            "KWP lockfile {} is inside a worker-writable input scope; input grants must be read-only",
            lockfile.display()
        );
    }
    let protected = relative == Path::new("kuzushi.lock")
        || relative == Path::new(".kuzushi")
        || relative.starts_with(".kuzushi");
    if protected {
        return Ok(());
    }
    anyhow::bail!(
        "KWP lockfile {} is inside the worker-writable workspace; use the protected workspace-root kuzushi.lock or an operator-owned path outside the target",
        lockfile.display()
    )
}

fn ensure_lockfile_is_outside_module_data(
    lockfile: &Path,
    verified: &VerifiedModule,
    workspace: &crate::workspace::WorkspaceTarget,
) -> Result<()> {
    if !verified.grant.allows_fs_write(FsScope::ModuleData) {
        return Ok(());
    }
    let digest = verified.digest.0.replace([':', '/', '\\'], "_");
    let module_data = workspace
        .state_dir()
        .join("kwp")
        .join("modules")
        .join(digest);
    let module_data = fs::canonicalize(&module_data).unwrap_or(module_data);
    if lockfile.starts_with(&module_data) {
        anyhow::bail!(
            "KWP lockfile {} is inside worker-writable module data; use an operator-owned path",
            lockfile.display()
        );
    }
    Ok(())
}

fn ensure_verified_bundle_is_current(specifier: &str, verified: &VerifiedModule) -> Result<()> {
    let resolved = resolve_file_worker_bundle(specifier)?;
    if resolved.digest != verified.digest
        || resolved.entry != verified.entry
        || resolved.tier != verified.tier
    {
        anyhow::bail!(
            "dynamic module bundle changed after approval; re-run `kuzushi kwp approve {specifier}`"
        );
    }
    Ok(())
}

fn ensure_verified_snapshot_is_current(verified: &VerifiedModule) -> Result<()> {
    let entry = verified.module_root.join(&verified.entry);
    let snapshot = resolve_file_worker_bundle(&entry.display().to_string())?;
    if snapshot.digest != verified.digest
        || snapshot.entry != verified.entry
        || snapshot.tier != verified.tier
    {
        anyhow::bail!("verified KWP bundle snapshot changed; reload the module");
    }
    Ok(())
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
        "context": dynamic_tool_context_json(ctx)?,
    });
    run_dynamic_host_with_runtime(specifier, name, payload, runtime, ctx.cancellation)
}

fn kwp_worker_command(specifier: &str, verified: &VerifiedModule) -> Result<Command> {
    if verified.tier != ExecutorTier::Node {
        anyhow::bail!("unsupported KWP worker tier {:?}", verified.tier);
    }
    let script = dynamic_host_script()?;
    let bundle_read_path = verified_worker_read_path(verified);
    let mut command = sandboxed_node_command(&script, &bundle_read_path)?;
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
    let bundle_read_path = resolved_worker_read_path(resolved);
    let mut command = sandboxed_node_command(&script, &bundle_read_path)?;
    command.arg(&script);
    command.args(args);
    Ok(command)
}

fn sandboxed_node_command(script: &Path, bundle_read_path: &Path) -> Result<Command> {
    ensure_node_network_permission_boundary()?;
    let mut command = isolated_node_command();
    command.arg("--permission");
    command.arg(format!("--allow-fs-read={}", script.display()));
    command.arg(format!("--allow-fs-read={}", bundle_read_path.display()));
    sanitize_worker_environment(&mut command);
    apply_dynamic_host_environment(&mut command);
    configure_dynamic_process_group(&mut command);
    Ok(command)
}

fn isolated_node_command() -> Command {
    #[cfg(target_os = "macos")]
    {
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command.args(["-p", "(version 1)(allow default)(deny network*)", "node"]);
        command
    }
    #[cfg(not(target_os = "macos"))]
    {
        Command::new("node")
    }
}

fn ensure_node_network_permission_boundary() -> Result<()> {
    static SUPPORT: OnceLock<std::result::Result<(), String>> = OnceLock::new();
    SUPPORT
        .get_or_init(check_node_network_permission_boundary)
        .clone()
        .map_err(anyhow::Error::msg)
}

#[cfg(test)]
pub(crate) fn kwp_node_execution_available() -> bool {
    ensure_node_network_permission_boundary().is_ok()
}

fn check_node_network_permission_boundary() -> std::result::Result<(), String> {
    let help_output = Command::new("node")
        .arg("--help")
        .output()
        .map_err(|error| {
            format!("could not inspect Node.js for KWP permission support: {error}")
        })?;
    if !help_output.status.success() {
        return Err("could not inspect Node.js for KWP permission support".to_string());
    }
    let help = String::from_utf8_lossy(&help_output.stdout);
    if !help.lines().any(|line| line.contains("--allow-net")) {
        return Err(
            "KWP Node workers require Node.js permission-mode network denial (`--allow-net`, Node 25 or newer)"
                .to_string(),
        );
    }
    ensure_network_permission_runtime_is_safe()?;
    probe_node_network_denial()?;
    Ok(())
}

fn probe_node_network_denial() -> std::result::Result<(), String> {
    let mut command = isolated_node_command();
    command.env_remove("NODE_OPTIONS");
    command
        .args(["--permission", "-e", KWP_NETWORK_DENIAL_PROBE])
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let child = command
        .spawn()
        .map_err(|error| format!("could not probe KWP Node network denial: {error}"))?;
    let status = wait_for_network_probe(child, Duration::from_secs(2))?;
    if status.code() == Some(13) {
        Ok(())
    } else {
        Err(format!(
            "KWP Node network-denial probe did not fail closed: {status}"
        ))
    }
}

const KWP_NETWORK_DENIAL_PROBE: &str = r#"
const socket = require('node:net').connect(9, '127.0.0.1');
socket.on('connect', () => process.exit(42));
socket.on('error', error => process.exit(
  error.code === 'ERR_ACCESS_DENIED' || error.code === 'EPERM' ? 13 : 43
));
setTimeout(() => process.exit(44), 500);
"#;

fn wait_for_network_probe(
    mut child: std::process::Child,
    timeout: Duration,
) -> std::result::Result<ExitStatus, String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("KWP network probe wait failed: {error}"))?
        {
            return Ok(status);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
    Err("KWP Node network-denial probe timed out".to_string())
}

#[cfg(target_os = "macos")]
fn ensure_network_permission_runtime_is_safe() -> std::result::Result<(), String> {
    Path::new("/usr/bin/sandbox-exec")
        .is_file()
        .then_some(())
        .ok_or_else(|| "KWP Node workers require the macOS sandbox executor".to_string())
}

#[cfg(not(target_os = "macos"))]
fn ensure_network_permission_runtime_is_safe() -> std::result::Result<(), String> {
    let output = Command::new("node")
        .arg("--version")
        .output()
        .map_err(|error| format!("could not inspect Node.js version: {error}"))?;
    let version = String::from_utf8_lossy(&output.stdout);
    if node_version_at_least(&version, (26, 3, 1)) {
        Ok(())
    } else {
        Err("KWP Node workers require Node.js 26.3.1 or newer on this platform".to_string())
    }
}

#[cfg(not(target_os = "macos"))]
fn node_version_at_least(version: &str, minimum: (u64, u64, u64)) -> bool {
    let mut parts = version.trim().trim_start_matches('v').split('.');
    let parsed = (
        parts.next().and_then(|part| part.parse().ok()),
        parts.next().and_then(|part| part.parse().ok()),
        parts.next().and_then(|part| part.parse().ok()),
    );
    matches!(parsed, (Some(major), Some(minor), Some(patch)) if (major, minor, patch) >= minimum)
}

fn worker_import_path(_specifier: &str, verified: &VerifiedModule) -> String {
    if verified.entry == "." {
        return verified.module_root.display().to_string();
    }
    verified
        .module_root
        .join(&verified.entry)
        .display()
        .to_string()
}

fn verified_worker_read_path(verified: &VerifiedModule) -> PathBuf {
    if verified.entry == "." {
        verified.module_root.clone()
    } else {
        verified.module_root.join(&verified.entry)
    }
}

fn resolved_worker_read_path(resolved: &ResolvedWorkerBundle) -> PathBuf {
    if resolved.entry == "." {
        resolved.module_root.clone()
    } else {
        resolved.module_root.join(&resolved.entry)
    }
}

fn resolved_worker_import_path(resolved: &ResolvedWorkerBundle) -> String {
    if resolved.entry == "." {
        resolved.module_root.display().to_string()
    } else {
        resolved
            .module_root
            .join(&resolved.entry)
            .display()
            .to_string()
    }
}

fn sanitize_worker_environment(command: &mut Command) {
    let inherited = ["PATH", "TMPDIR", "TEMP", "TMP"].map(|name| (name, std::env::var_os(name)));
    command.env_clear();
    for (name, value) in inherited {
        if let Some(value) = value {
            command.env(name, value);
        }
    }
}

trait DynamicToolContext {
    fn configured_cwd_for_dynamic_tool(&self) -> Result<String>;
}

impl DynamicToolContext for ToolExecutionContext<'_> {
    fn configured_cwd_for_dynamic_tool(&self) -> Result<String> {
        self.workspace
            .map(|workspace| workspace.root().display().to_string())
            .context(
                "dynamic tools require an explicit active workspace; cwd fallback is forbidden",
            )
    }
}

fn validate_dynamic_module_shape(loaded: &mut DynamicModuleDescription) -> Result<()> {
    validate_dynamic_module_id(&loaded.module.id)?;
    // `hidden` exists for built-in DAG-internal nodes. A dynamic module or
    // tool that is dispatchable but absent from `/use` and the tool list
    // would evade operator review, so approved KWP surface must stay
    // visible until dynamic DAG scheduling is a real, reviewed feature.
    if loaded.hidden {
        anyhow::bail!(
            "dynamic module {:?} cannot be hidden; approved KWP modules must stay operator-visible",
            loaded.module.id
        );
    }
    let mut tool_names = BTreeSet::new();
    for tool in &mut loaded.tools {
        validate_dynamic_tool_name(&loaded.module.id, &tool.name)?;
        if !tool_names.insert(tool.name.clone()) {
            anyhow::bail!("dynamic module declares duplicate tool {:?}", tool.name);
        }
        validate_dynamic_tool_options(tool)?;
        validate_dynamic_tool_policy(tool)?;
    }
    Ok(())
}

fn validate_dynamic_tool_policy(tool: &ToolDescriptor) -> Result<()> {
    if tool.hidden {
        anyhow::bail!(
            "dynamic tool {:?} cannot be hidden; a dispatchable but unlisted dynamic tool would evade operator review",
            tool.name
        );
    }
    if tool.runtime_requirement == RuntimeRequirement::InputAware {
        anyhow::bail!(
            "dynamic tool {:?} cannot declare input-aware runtime policy without a native predicate",
            tool.name
        );
    }
    if tool.effect.needs_operator_approval() && tool.approval != ApprovalPolicy::Explicit {
        anyhow::bail!(
            "dynamic tool {:?} declares {:?} but does not require explicit approval",
            tool.name,
            tool.effect
        );
    }
    if super::autonomy::classify_descriptor(tool).is_none() {
        anyhow::bail!(
            "dynamic tool {:?} must declare map|scan|review|prove|fix|report with a compatible effect",
            tool.name
        );
    }
    validate_prompt_options(&tool, "dynamic tool")?;
    Ok(())
}

fn validate_dynamic_module_id(module_id: &str) -> Result<()> {
    let mut chars = module_id.chars();
    let valid_first = chars.next().is_some_and(|ch| ch.is_ascii_lowercase());
    let valid_rest = chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-');
    if valid_first && valid_rest {
        return Ok(());
    }
    anyhow::bail!("dynamic module id {module_id:?} must match ^[a-z][a-z0-9-]*$")
}

fn validate_dynamic_tool_name(module_id: &str, name: &str) -> Result<()> {
    let Some((prefix, action)) = name.split_once(':') else {
        anyhow::bail!("dynamic tool {name:?} must use <moduleId>:<action>");
    };
    if prefix != module_id {
        anyhow::bail!("dynamic tool {name:?} must start with module id {module_id:?}");
    }
    let mut chars = action.chars();
    let valid_first = chars.next().is_some_and(|ch| ch.is_ascii_lowercase());
    let valid_rest =
        chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '-' | '_'));
    if valid_first && valid_rest {
        return Ok(());
    }
    anyhow::bail!("dynamic tool {name:?} has an invalid action name")
}

fn validate_dynamic_tool_options(tool: &mut ToolDescriptor) -> Result<()> {
    let mut names = BTreeSet::new();
    for option in &mut tool.options {
        validate_dynamic_option_names(&tool.name, option, &mut names)?;
        validate_dynamic_enum_choices(&tool.name, option)?;
        validate_dynamic_integer_range(&tool.name, option)?;
        normalize_dynamic_option_default(&tool.name, option)?;
        if option.option_type == OptionType::Path && option.path_semantics.is_none() {
            anyhow::bail!(
                "dynamic tool {:?} path option {:?} must declare pathSemantics",
                tool.name,
                option.name
            )
        }
    }
    Ok(())
}

fn validate_dynamic_integer_range(tool_name: &str, option: &OptionSpec) -> Result<()> {
    let has_range = option.minimum.is_some() || option.maximum.is_some();
    anyhow::ensure!(
        !has_range || option.option_type == OptionType::Int,
        "dynamic tool {tool_name:?} option {:?} declares an integer range for a non-integer type",
        option.name
    );
    if let (Some(minimum), Some(maximum)) = (option.minimum, option.maximum) {
        anyhow::ensure!(
            minimum <= maximum,
            "dynamic tool {tool_name:?} option {:?} has minimum {minimum} above maximum {maximum}",
            option.name
        );
    }
    Ok(())
}

fn validate_dynamic_option_names(
    tool_name: &str,
    option: &OptionSpec,
    names: &mut BTreeSet<String>,
) -> Result<()> {
    for name in std::iter::once(&option.name)
        .chain(&option.aliases)
        .chain(&option.deprecated_aliases)
    {
        if name.trim().is_empty() {
            anyhow::bail!("dynamic tool {tool_name:?} has an empty option name or alias");
        }
        if !names.insert(name.to_ascii_lowercase()) {
            anyhow::bail!(
                "dynamic tool {tool_name:?} declares duplicate option name or alias {name:?}"
            );
        }
    }
    Ok(())
}

fn validate_dynamic_enum_choices(tool_name: &str, option: &OptionSpec) -> Result<()> {
    if option.option_type == OptionType::Enum && option.choices.is_empty() {
        anyhow::bail!(
            "dynamic tool {tool_name:?} enum option {:?} must declare choices",
            option.name
        );
    }
    Ok(())
}

fn normalize_dynamic_option_default(tool_name: &str, option: &mut OptionSpec) -> Result<()> {
    let Some(default) = option.default.take() else {
        return Ok(());
    };
    option.default = Some(coerce_option_value(option, default).with_context(|| {
        format!(
            "dynamic tool {tool_name:?} has an invalid default for option {:?}",
            option.name
        )
    })?);
    Ok(())
}

fn dynamic_tool_context_json(ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let cwd = ctx.configured_cwd_for_dynamic_tool()?;
    Ok(json!({
        "cwd": cwd,
        "target": cwd,
        "config": ctx.config,
    }))
}

const DYNAMIC_DESCRIBE_TIMEOUT: Duration = Duration::from_secs(30);
const DYNAMIC_EXECUTE_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_DYNAMIC_STDOUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_DYNAMIC_STDERR_BYTES: usize = 64 * 1024;

fn run_dynamic_host<const N: usize>(
    args: [&str; N],
    stdin: Option<Vec<u8>>,
    cancellation: Option<&crate::scan::ScanCancellation>,
) -> Result<Vec<u8>> {
    let timeout = dynamic_host_timeout(args.first().copied());
    let command = dynamic_host_command(args)?;
    run_dynamic_host_command(command, stdin, cancellation, timeout)
}

fn run_dynamic_host_command(
    command: Command,
    stdin: Option<Vec<u8>>,
    cancellation: Option<&crate::scan::ScanCancellation>,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let mut child = spawn_dynamic_host(command, stdin.is_some())?;
    let child_stdin = child.stdin.take();
    let (stdout, stderr, pipe_failure) = take_dynamic_host_readers(&mut child)?;
    let registered = register_dynamic_child(child, cancellation)?;
    if let Err(error) = write_dynamic_host_input(child_stdin, stdin) {
        let _ = registered.kill_and_wait();
        let _ = join_dynamic_pipe_reader(stdout, "stdout");
        let _ = join_dynamic_pipe_reader(stderr, "stderr");
        return Err(error);
    }
    let status = wait_dynamic_child(&registered, timeout, cancellation, &pipe_failure)?;
    let output = collect_dynamic_host_output(status, stdout, stderr)?;
    decode_dynamic_host_envelope(&output)
}

fn decode_dynamic_host_envelope(output: &[u8]) -> Result<Vec<u8>> {
    let envelope: Value = serde_json::from_slice(output)
        .context("dynamic module host omitted its versioned protocol envelope")?;
    validate_dynamic_host_handshake(&envelope)?;
    let payload = envelope
        .get("payload")
        .context("dynamic module host protocol envelope omitted payload")?;
    serde_json::to_vec(payload).context("could not decode dynamic module host payload")
}

pub(super) fn validate_dynamic_host_handshake(message: &Value) -> Result<()> {
    let protocol = message
        .get("protocolVersion")
        .and_then(Value::as_u64)
        .context("dynamic module host handshake omitted protocolVersion")?;
    if protocol != DYNAMIC_HOST_PROTOCOL_VERSION {
        anyhow::bail!(
            "dynamic module host protocol mismatch: native={} host={protocol}",
            DYNAMIC_HOST_PROTOCOL_VERSION
        )
    }
    let host_version = message
        .get("hostVersion")
        .and_then(Value::as_str)
        .context("dynamic module host handshake omitted hostVersion")?;
    if host_version != DYNAMIC_HOST_SDK_VERSION {
        anyhow::bail!(
            "dynamic module host version mismatch: native={} host={host_version}",
            DYNAMIC_HOST_SDK_VERSION
        )
    }
    Ok(())
}

fn dynamic_host_timeout(command: Option<&str>) -> Duration {
    match command {
        Some("describe") => DYNAMIC_DESCRIBE_TIMEOUT,
        _ => DYNAMIC_EXECUTE_TIMEOUT,
    }
}

fn spawn_dynamic_host(mut command: Command, piped_stdin: bool) -> Result<std::process::Child> {
    if piped_stdin {
        command.stdin(Stdio::piped());
    }
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("could not start node dynamic module host")
}

fn write_dynamic_host_input(
    child_stdin: Option<std::process::ChildStdin>,
    input: Option<Vec<u8>>,
) -> Result<()> {
    let Some(input) = input else {
        return Ok(());
    };
    let mut child_stdin = child_stdin.context("dynamic module host stdin was unavailable")?;
    child_stdin
        .write_all(&input)
        .context("could not write dynamic module host request")
}

type DynamicPipeReader = std::thread::JoinHandle<Result<Vec<u8>>>;

fn take_dynamic_host_readers(
    child: &mut std::process::Child,
) -> Result<(DynamicPipeReader, DynamicPipeReader, DynamicPipeFailure)> {
    let failure = Arc::new(Mutex::new(None));
    let stdout = spawn_dynamic_pipe_reader(
        child.stdout.take(),
        MAX_DYNAMIC_STDOUT_BYTES,
        "stdout",
        Arc::clone(&failure),
    )?;
    let stderr = spawn_dynamic_pipe_reader(
        child.stderr.take(),
        MAX_DYNAMIC_STDERR_BYTES,
        "stderr",
        Arc::clone(&failure),
    )?;
    Ok((stdout, stderr, failure))
}

fn collect_dynamic_host_output(
    status: ExitStatus,
    stdout: DynamicPipeReader,
    stderr: DynamicPipeReader,
) -> Result<Vec<u8>> {
    let stdout = join_dynamic_pipe_reader(stdout, "stdout")?;
    let stderr = join_dynamic_pipe_reader(stderr, "stderr")?;
    if !status.success() {
        anyhow::bail!(
            "dynamic module host failed: {}",
            String::from_utf8_lossy(&stderr).trim()
        );
    }
    Ok(stdout)
}

fn spawn_dynamic_pipe_reader<R: Read + Send + 'static>(
    pipe: Option<R>,
    limit: usize,
    label: &'static str,
    failure: DynamicPipeFailure,
) -> Result<std::thread::JoinHandle<Result<Vec<u8>>>> {
    let mut pipe = pipe.with_context(|| format!("dynamic module host {label} was unavailable"))?;
    Ok(std::thread::spawn(move || {
        match read_dynamic_pipe(&mut pipe, limit, label) {
            Ok(bytes) => Ok(bytes),
            Err(error) => {
                if let Ok(mut slot) = failure.lock() {
                    *slot = Some(error.to_string());
                }
                Err(error)
            }
        }
    }))
}

type DynamicPipeFailure = Arc<Mutex<Option<String>>>;

fn read_dynamic_pipe(reader: &mut impl Read, limit: usize, label: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("could not read dynamic module host {label}"))?;
    if bytes.len() > limit {
        anyhow::bail!("dynamic module host {label} exceeded {limit} bytes")
    }
    Ok(bytes)
}

fn join_dynamic_pipe_reader(
    reader: std::thread::JoinHandle<Result<Vec<u8>>>,
    label: &str,
) -> Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("dynamic module host {label} reader panicked"))?
}

fn register_dynamic_child(
    child: std::process::Child,
    cancellation: Option<&crate::scan::ScanCancellation>,
) -> Result<crate::scan::RegisteredChild> {
    let local;
    let cancellation = match cancellation {
        Some(cancellation) => cancellation,
        None => {
            local = crate::scan::ScanCancellation::default();
            &local
        }
    };
    let process_group_id = dynamic_child_process_group_id(&child);
    cancellation.register_child(child, process_group_id)
}

fn wait_dynamic_child(
    child: &crate::scan::RegisteredChild,
    timeout: Duration,
    cancellation: Option<&crate::scan::ScanCancellation>,
    pipe_failure: &DynamicPipeFailure,
) -> Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        cancel_dynamic_child_if_requested(child, cancellation)?;
        fail_dynamic_child_on_pipe_error(child, pipe_failure)?;
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        timeout_dynamic_child_if_expired(child, deadline, timeout)?;
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn fail_dynamic_child_on_pipe_error(
    child: &crate::scan::RegisteredChild,
    pipe_failure: &DynamicPipeFailure,
) -> Result<()> {
    let failure = pipe_failure
        .lock()
        .map_err(|_| anyhow::anyhow!("dynamic module host pipe failure state was poisoned"))?
        .clone();
    if let Some(failure) = failure {
        child.kill_and_wait()?;
        anyhow::bail!(failure)
    }
    Ok(())
}

fn cancel_dynamic_child_if_requested(
    child: &crate::scan::RegisteredChild,
    cancellation: Option<&crate::scan::ScanCancellation>,
) -> Result<()> {
    if cancellation.is_some_and(crate::scan::ScanCancellation::is_cancelled) {
        child.kill_and_wait()?;
        anyhow::bail!("dynamic module host was cancelled and killed")
    }
    Ok(())
}

fn timeout_dynamic_child_if_expired(
    child: &crate::scan::RegisteredChild,
    deadline: Instant,
    timeout: Duration,
) -> Result<()> {
    if Instant::now() >= deadline {
        child.kill_and_wait()?;
        anyhow::bail!(
            "dynamic module host timed out after {}s and was killed",
            timeout.as_secs()
        )
    }
    Ok(())
}

pub(super) fn dynamic_host_command<const N: usize>(args: [&str; N]) -> Result<Command> {
    let mut command = Command::new("node");
    command.arg(dynamic_host_script()?);
    command.args(args);
    apply_dynamic_host_environment(&mut command);
    configure_dynamic_process_group(&mut command);
    Ok(command)
}

fn apply_dynamic_host_environment(command: &mut Command) {
    command.env(
        "KUZUSHI_DYNAMIC_HOST_PROTOCOL_VERSION",
        DYNAMIC_HOST_PROTOCOL_VERSION.to_string(),
    );
    command.env("KUZUSHI_HOST_VERSION", DYNAMIC_HOST_SDK_VERSION);
}

#[cfg(unix)]
fn configure_dynamic_process_group(command: &mut Command) {
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn configure_dynamic_process_group(_command: &mut Command) {}

#[cfg(unix)]
fn dynamic_child_process_group_id(child: &std::process::Child) -> Option<u32> {
    Some(child.id())
}

#[cfg(not(unix))]
fn dynamic_child_process_group_id(_child: &std::process::Child) -> Option<u32> {
    None
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
    fn retired_builtin_ids_remain_reserved_for_run_provenance() {
        assert!(retired_builtin_module_id("smoke"));
        assert!(retired_builtin_module_id("pwn"));
        assert!(!retired_builtin_module_id("third-party-module"));
    }

    #[test]
    fn approved_worker_snapshot_path_remains_bound_after_source_changes() {
        let source = tempfile::tempdir().unwrap();
        let entry = source.path().join("worker.mjs");
        fs::write(&entry, "export const version = 1;\n").unwrap();
        let specifier = entry.display().to_string();
        let resolved = resolve_file_worker_bundle(&specifier).unwrap();
        let approval = LockfileEntry {
            module_id: crate::worker_protocol::ModuleId("snapshot-test".to_string()),
            digest: resolved.digest.clone(),
            version: "1.0.0".to_string(),
            descriptor_hash: "sha256:test-descriptor".to_string(),
            grant: Grant::default(),
            signature_chain: Vec::new(),
            revoked: false,
        };
        let (_snapshot, staged) = snapshot_worker_bundle(&resolved).unwrap();
        let verified = verified_module_from_snapshot(&resolved, staged, &approval);

        fs::write(&entry, "export const version = 2;\n").unwrap();

        let changed = ensure_verified_bundle_is_current(&specifier, &verified)
            .unwrap_err()
            .to_string();
        assert!(changed.contains("changed after approval"), "{changed}");
        ensure_verified_snapshot_is_current(&verified).unwrap();
        assert_eq!(
            PathBuf::from(worker_import_path(&specifier, &verified)),
            verified.module_root.join(&verified.entry)
        );
        assert_ne!(
            PathBuf::from(worker_import_path(&specifier, &verified)),
            entry
        );
    }

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

    #[test]
    fn single_file_worker_permission_does_not_expose_its_parent_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let host_dir = tmp.path().join("host");
        let module_dir = tmp.path().join("module");
        fs::create_dir_all(&host_dir).unwrap();
        fs::create_dir_all(&module_dir).unwrap();
        let script = host_dir.join("host.mjs");
        let entry = module_dir.join("entry.mjs");

        let command = sandboxed_node_command(&script, &entry).unwrap();
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert!(args.contains(&format!("--allow-fs-read={}", script.display())));
        assert!(args.contains(&format!("--allow-fs-read={}", entry.display())));
        assert!(!args.contains(&format!("--allow-fs-read={}", module_dir.display())));
        assert!(!args.contains(&format!("--allow-fs-read={}", host_dir.display())));
    }

    #[test]
    fn kwp_node_permission_boundary_denies_direct_network_access() {
        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("host.mjs");
        let entry = tmp.path().join("entry.mjs");
        fs::write(&script, "").unwrap();
        fs::write(&entry, "").unwrap();
        let mut command = sandboxed_node_command(&script, &entry).unwrap();
        let output = command
            .args(["-e", KWP_NETWORK_DENIAL_PROBE])
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(13));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn kwp_macos_sandbox_denies_network_even_if_node_permission_is_relaxed() {
        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("host.mjs");
        let entry = tmp.path().join("entry.mjs");
        fs::write(&script, "").unwrap();
        fs::write(&entry, "").unwrap();
        let mut command = sandboxed_node_command(&script, &entry).unwrap();
        let output = command
            .args(["--allow-net", "-e", KWP_NETWORK_DENIAL_PROBE])
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(13));
    }

    #[test]
    fn dynamic_child_timeout_kills_the_process_group() {
        let child = sleeping_node_child();
        let child = register_dynamic_child(child, None).unwrap();
        let pipe_failure = Arc::new(Mutex::new(None));

        let error = wait_dynamic_child(&child, Duration::from_millis(20), None, &pipe_failure)
            .unwrap_err()
            .to_string();

        assert!(error.contains("timed out"), "{error}");
    }

    #[test]
    fn dynamic_child_cancellation_kills_the_process_group() {
        let cancellation = crate::scan::ScanCancellation::default();
        let child = sleeping_node_child();
        let child = register_dynamic_child(child, Some(&cancellation)).unwrap();
        cancellation.cancel();
        let pipe_failure = Arc::new(Mutex::new(None));

        let error = wait_dynamic_child(
            &child,
            Duration::from_secs(1),
            Some(&cancellation),
            &pipe_failure,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("cancelled and killed"), "{error}");
    }

    #[test]
    fn dynamic_pipe_failure_kills_child_without_waiting_for_timeout() {
        let child = sleeping_node_child();
        let child = register_dynamic_child(child, None).unwrap();
        let pipe_failure = Arc::new(Mutex::new(Some("stdout exceeded limit".to_string())));

        let error = wait_dynamic_child(&child, Duration::from_secs(60), None, &pipe_failure)
            .unwrap_err()
            .to_string();

        assert!(error.contains("stdout exceeded limit"), "{error}");
    }

    #[test]
    fn dynamic_pipe_reader_rejects_output_above_its_bound() {
        let mut output = std::io::Cursor::new(vec![b'x'; 18]);

        let error = read_dynamic_pipe(&mut output, 16, "stdout")
            .unwrap_err()
            .to_string();

        assert!(error.contains("stdout exceeded 16 bytes"), "{error}");
    }

    #[test]
    fn unversioned_dynamic_host_output_is_rejected() {
        let error = decode_dynamic_host_envelope(br#"{"payload":{}}"#)
            .unwrap_err()
            .to_string();

        assert!(error.contains("protocolVersion"), "{error}");
    }

    #[test]
    fn mismatched_dynamic_host_protocol_is_rejected() {
        let output = serde_json::to_vec(&json!({
            "protocolVersion": DYNAMIC_HOST_PROTOCOL_VERSION + 1,
            "hostVersion": DYNAMIC_HOST_SDK_VERSION,
            "payload": {},
        }))
        .unwrap();
        let error = decode_dynamic_host_envelope(&output)
            .unwrap_err()
            .to_string();

        assert!(error.contains("protocol mismatch"), "{error}");
    }

    #[test]
    fn mismatched_dynamic_host_version_is_rejected() {
        let output = serde_json::to_vec(&json!({
            "protocolVersion": DYNAMIC_HOST_PROTOCOL_VERSION,
            "hostVersion": "0.0.0-incompatible",
            "payload": {},
        }))
        .unwrap();
        let error = decode_dynamic_host_envelope(&output)
            .unwrap_err()
            .to_string();

        assert!(error.contains("version mismatch"), "{error}");
    }

    #[test]
    fn compatibility_specifiers_cannot_alias_local_files() {
        for specifier in [
            "file:/tmp/module.mjs",
            "package:file:/tmp/module.mjs",
            "package:./module.mjs",
            "package:../module.mjs",
            "package:/tmp/module.mjs",
            "mcp:local",
        ] {
            assert!(
                ensure_package_compatibility_specifier(specifier).is_err(),
                "accepted {specifier}"
            );
        }
        assert!(ensure_package_compatibility_specifier("package:example-module").is_ok());
        assert!(ensure_package_compatibility_specifier("package:@scope/example/subpath").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn dynamic_loader_rejects_a_symlink_lockfile() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("actual.lock");
        let link = tmp.path().join("kuzushi.lock");
        fs::write(&target, r#"{"modules":{}}"#).unwrap();
        symlink(&target, &link).unwrap();
        let options = DynamicModuleLoadOptions {
            trusted_specifiers: Vec::new(),
            lockfile_path: Some(link),
        };

        let error = dynamic_lockfile_path(&options).unwrap_err().to_string();

        assert!(error.contains("must not contain symlinks"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn dynamic_loader_rejects_a_symlinked_lockfile_parent() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let actual = tmp.path().join("actual");
        let alias = tmp.path().join("alias");
        fs::create_dir(&actual).unwrap();
        fs::write(actual.join("kuzushi.lock"), r#"{"modules":{}}"#).unwrap();
        symlink(&actual, &alias).unwrap();
        let options = DynamicModuleLoadOptions {
            trusted_specifiers: Vec::new(),
            lockfile_path: Some(alias.join("kuzushi.lock")),
        };

        let error = dynamic_lockfile_path(&options).unwrap_err().to_string();

        assert!(error.contains("must not contain symlinks"), "{error}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn dynamic_loader_normalizes_only_known_macos_system_aliases() {
        assert_eq!(
            normalize_platform_lockfile_path(Path::new("/var/folders/example/kuzushi.lock")),
            PathBuf::from("/private/var/folders/example/kuzushi.lock")
        );
        assert_eq!(
            normalize_platform_lockfile_path(Path::new("/tmp/example/kuzushi.lock")),
            PathBuf::from("/private/tmp/example/kuzushi.lock")
        );
    }

    #[test]
    fn dynamic_input_aware_runtime_policy_is_rejected_without_a_native_predicate() {
        let mut descriptor = tool("example:run", "example");
        descriptor.runtime_requirement = RuntimeRequirement::InputAware;
        descriptor.effect = ToolEffect::Read;

        let error = validate_dynamic_tool_policy(&descriptor)
            .unwrap_err()
            .to_string();

        assert!(error.contains("native predicate"), "{error}");
    }

    #[test]
    fn hidden_dynamic_tools_and_modules_are_rejected() {
        let mut descriptor = tool("example:run", "example");
        descriptor.hidden = true;
        descriptor.effect = ToolEffect::Read;

        let error = validate_dynamic_tool_policy(&descriptor)
            .unwrap_err()
            .to_string();
        assert!(error.contains("evade operator review"), "{error}");
    }

    #[test]
    fn dynamic_integer_ranges_are_type_checked() {
        let option = opt("label", OptionType::String, "label").integer_range(1, 2);

        let error = validate_dynamic_integer_range("example:run", &option)
            .unwrap_err()
            .to_string();

        assert!(error.contains("non-integer type"), "{error}");
    }

    #[test]
    fn dynamic_integer_ranges_reject_reversed_bounds() {
        let option = opt("count", OptionType::Int, "count").integer_range(2, 1);

        let error = validate_dynamic_integer_range("example:run", &option)
            .unwrap_err()
            .to_string();

        assert!(error.contains("minimum 2 above maximum 1"), "{error}");
    }

    fn sleeping_node_child() -> std::process::Child {
        let mut command = Command::new("node");
        command
            .args(["-e", "setTimeout(() => {}, 60_000)"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_dynamic_process_group(&mut command);
        command.spawn().unwrap()
    }
}

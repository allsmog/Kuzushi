mod observation;
mod policy;
mod policy_validation;
mod snapshot;
mod wasm;

#[cfg(test)]
mod tests;

use crate::identity::Blake3Hash;
use crate::storage_v3::writer_actor::{
    StorageWriterActor, WatcherCommand, WriteReceipt, WriterCommand,
};
use anyhow::{bail, Context, Result};
use kuzushi_sandbox::{
    detect_backend, sandbox_exec, ExitOutcome, SandboxBackend, SandboxExecOptions,
    SandboxExecResult,
};
use observation::candidate_observation_write;
use policy_validation::validate_invocation_policy;
pub use policy::{EnvPolicy, NetworkPolicy, SandboxPolicy, SubprocessPolicy};
pub use snapshot::{GrantedBlob, GrantedSnapshot};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
pub use wasm::{run_wasm_plugin_invocation, WasmPluginInvocation};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct UntrustedFindingCandidate {
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub blob_hash: Blake3Hash,
    pub byte_start: u64,
    pub byte_end: u64,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedFindingCandidate(UntrustedFindingCandidate);

impl ValidatedFindingCandidate {
    pub fn into_inner(self) -> UntrustedFindingCandidate {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginSandboxInvocation {
    pub command: Vec<String>,
    pub policy: SandboxPolicy,
    pub grant: GrantedSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "backend")]
pub enum PluginSandboxBackend {
    Process(SandboxBackend),
    Wasmtime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginSandboxResult {
    pub backend: PluginSandboxBackend,
    pub duration_ms: u64,
    pub findings: Vec<ValidatedFindingCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginObservationContext {
    pub snapshot_hash: String,
    pub run_id: String,
    pub tool: String,
    pub tool_version: Option<String>,
    pub rule_set_hash: Option<String>,
    pub actor: String,
    pub display_paths: BTreeMap<Blake3Hash, String>,
    pub languages: BTreeMap<Blake3Hash, String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub(super) struct PluginStdout {
    #[serde(default)]
    findings: Vec<UntrustedFindingCandidate>,
}

pub async fn run_plugin_invocation(
    invocation: PluginSandboxInvocation,
) -> Result<PluginSandboxResult> {
    let backend = detect_backend(None);
    if !backend.is_isolating() {
        bail!("no isolating sandbox backend is available for untrusted plugin execution");
    }
    run_plugin_invocation_with_backend(invocation, backend).await
}

pub fn validate_candidate(
    candidate: UntrustedFindingCandidate,
    grant: &GrantedSnapshot,
) -> Result<ValidatedFindingCandidate> {
    validate_candidate_with_field_cap(candidate, grant, SandboxPolicy::default().max_field_bytes)
}

fn validate_candidate_with_field_cap(
    candidate: UntrustedFindingCandidate,
    grant: &GrantedSnapshot,
    max_field_bytes: u64,
) -> Result<ValidatedFindingCandidate> {
    require_non_empty("rule_id", &candidate.rule_id)?;
    require_non_empty("title", &candidate.title)?;
    require_non_empty("message", &candidate.message)?;
    require_field_cap("rule_id", &candidate.rule_id, max_field_bytes)?;
    require_field_cap("title", &candidate.title, max_field_bytes)?;
    require_field_cap("severity", &candidate.severity, max_field_bytes)?;
    require_field_cap("message", &candidate.message, max_field_bytes)?;
    require_severity(&candidate.severity)?;
    let Some(blob_size) = grant.blob_size(&candidate.blob_hash) else {
        bail!("plugin finding references a blob outside its granted snapshot");
    };
    if candidate.byte_start >= candidate.byte_end || candidate.byte_end > blob_size {
        bail!("plugin finding byte span is outside the granted blob");
    }
    Ok(ValidatedFindingCandidate(candidate))
}

pub fn record_plugin_findings_with_actor(
    log_dir: impl Into<PathBuf>,
    projection_path: impl Into<PathBuf>,
    context: &PluginObservationContext,
    grant: &GrantedSnapshot,
    findings: Vec<ValidatedFindingCandidate>,
) -> Result<Vec<WriteReceipt>> {
    let commands = findings
        .into_iter()
        .map(|finding| {
            let candidate = candidate_observation_write(finding, context, grant)?;
            Ok(WriterCommand::Watcher(WatcherCommand::CandidateObservation(
                candidate,
            )))
        })
        .collect::<Result<Vec<_>>>()?;
    StorageWriterActor::commit_blocking_many(log_dir, projection_path, commands)
}

fn require_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("plugin finding {field} cannot be empty");
    }
    Ok(())
}

fn require_field_cap(field: &str, value: &str, max_field_bytes: u64) -> Result<()> {
    if value.len() as u64 > max_field_bytes {
        bail!(
            "plugin finding {field} is {} bytes, exceeding policy cap {max_field_bytes}",
            value.len()
        );
    }
    Ok(())
}

fn require_severity(value: &str) -> Result<()> {
    match value {
        "critical" | "high" | "medium" | "low" | "info" => Ok(()),
        _ => bail!("plugin finding severity is not allowed"),
    }
}

async fn run_plugin_invocation_with_backend(
    invocation: PluginSandboxInvocation,
    backend: SandboxBackend,
) -> Result<PluginSandboxResult> {
    validate_invocation_policy(&invocation)?;
    let output = sandbox_exec(backend, sandbox_options(&invocation)?)
        .await
        .context("plugin sandbox execution failed")?;
    plugin_result_from_output(output, &invocation.grant, &invocation.policy)
}

fn sandbox_options(invocation: &PluginSandboxInvocation) -> Result<SandboxExecOptions> {
    let mut options = SandboxExecOptions::new(invocation.command.clone());
    options.timeout_ms = invocation.policy.timeout_ms;
    options.memory_mb = Some(invocation.policy.memory_limit_bytes.div_ceil(1024 * 1024));
    options.network = false;
    options.env.clear();
    options.read_only_mounts = if invocation.policy.read_snapshot {
        invocation.grant.read_only_mounts()
    } else {
        Vec::new()
    };
    options.stdin = Some(plugin_manifest_json(
        &invocation.grant,
        invocation.policy.read_snapshot,
    )?);
    Ok(options)
}

fn plugin_result_from_output(
    output: SandboxExecResult,
    grant: &GrantedSnapshot,
    policy: &SandboxPolicy,
) -> Result<PluginSandboxResult> {
    if output.outcome != ExitOutcome::Exited || output.exit_code != Some(0) {
        bail!(
            "plugin sandbox exited unsuccessfully: {}",
            output.stderr.trim()
        );
    }
    let findings = validate_plugin_stdout(&output.stdout, grant, policy)?;
    Ok(PluginSandboxResult {
        backend: PluginSandboxBackend::Process(output.backend),
        duration_ms: output.duration_ms,
        findings,
    })
}

pub(super) fn validate_plugin_stdout(
    stdout: &str,
    grant: &GrantedSnapshot,
    policy: &SandboxPolicy,
) -> Result<Vec<ValidatedFindingCandidate>> {
    if stdout.len() as u64 > policy.max_output_bytes {
        bail!(
            "plugin returned {} output bytes, exceeding policy cap {}",
            stdout.len(),
            policy.max_output_bytes
        );
    }
    let stdout: PluginStdout = serde_json::from_str(stdout)
        .map_err(|error| anyhow::anyhow!("plugin returned invalid JSON: {error}"))?;
    if stdout.findings.len() > policy.max_findings_returned as usize {
        bail!(
            "plugin returned {} findings, exceeding policy cap {}",
            stdout.findings.len(),
            policy.max_findings_returned
        );
    }
    stdout
        .findings
        .into_iter()
        .map(|candidate| {
            validate_candidate_with_field_cap(candidate, grant, policy.max_field_bytes)
        })
        .collect()
}

pub(super) fn plugin_manifest_json(grant: &GrantedSnapshot, include_paths: bool) -> Result<String> {
    snapshot::plugin_manifest_json(grant, include_paths)
}

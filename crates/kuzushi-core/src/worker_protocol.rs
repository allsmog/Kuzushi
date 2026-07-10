//! Kuzushi Worker Protocol (KWP) v0.1 host primitives.
//!
//! This module implements the policy/data surface for out-of-process modules:
//! digest-pinned trust, immutable grants, invocation-scoped broker checks,
//! host-mediated MCP composition, fuzz execution delegation, audit records,
//! JSON-RPC message shapes, and supervisor/executor seams.

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest as _;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::Mutex;
use url::Url;

pub const KWP_VERSION: &str = "0.1.0";
pub const METHOD_MCP_CALL: &str = "kuzushi/mcp/call";
pub const METHOD_FUZZ_RUN: &str = "kuzushi/fuzz/run";
pub const METHOD_MODULE_RUN: &str = "kuzushi/module/run";
pub const METHOD_FS_READ: &str = "kuzushi/fs/read";
pub const METHOD_FS_WRITE: &str = "kuzushi/fs/write";
pub const METHOD_FS_LIST: &str = "kuzushi/fs/list";
pub const METHOD_FS_STAT: &str = "kuzushi/fs/stat";
pub const METHOD_FS_REMOVE: &str = "kuzushi/fs/remove";
pub const METHOD_RUNTIME_QUERY: &str = "kuzushi/runtime/query";
pub const METHOD_FINDINGS_CREATE: &str = "kuzushi/findings/create";
pub const METHOD_ARTIFACTS_RECORD: &str = "kuzushi/artifacts/record";
pub const METHOD_NET_FETCH: &str = "kuzushi/net/fetch";
pub const METHOD_BUS_PUBLISH: &str = "kuzushi/bus/publish";

const KWP_CANCEL_GRACE: Duration = Duration::from_millis(250);
const KWP_WORKER_EPOCH: u64 = 1;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ModuleId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Digest(pub String);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct InvocationId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RunId(pub String);

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum KwpError {
    #[error("no active invocation")]
    NoActiveInvocation,
    #[error("capability not granted: {0}")]
    NotGranted(String),
    #[error("quota exceeded: {0}")]
    QuotaExceeded(String),
    #[error("runtime budget exceeded")]
    RuntimeBudget,
    #[error("epoch stale")]
    EpochStale,
    #[error("deadline exceeded")]
    Deadline,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl KwpError {
    pub fn code(&self) -> i32 {
        match self {
            Self::NoActiveInvocation => -32030,
            Self::NotGranted(_) => -32031,
            Self::QuotaExceeded(_) => -32032,
            Self::RuntimeBudget => -32033,
            Self::EpochStale => -32034,
            Self::Deadline => -32035,
            Self::BadRequest(_) => -32602,
            Self::Internal(_) => -32603,
        }
    }

    pub fn denied(capability: impl Into<String>) -> Self {
        Self::NotGranted(capability.into())
    }

    pub fn quota(resource: impl Into<String>) -> Self {
        Self::QuotaExceeded(resource.into())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    #[serde(default)]
    pub fs: Vec<FsScopeGrant>,
    #[serde(default)]
    pub net: Option<NetGrant>,
    #[serde(default)]
    pub runtime: Option<RuntimeGrant>,
    #[serde(default)]
    pub bus: BusGrant,
    #[serde(default)]
    pub findings: Option<FindingsGrant>,
    #[serde(default)]
    pub artifacts: Option<ArtifactsGrant>,
    #[serde(default)]
    pub mcp: Vec<McpGrant>,
    #[serde(default)]
    pub fuzz: Option<FuzzGrant>,
    #[serde(default)]
    pub exec: Option<Vec<ExecGrant>>,
    #[serde(default)]
    pub init_capabilities: InitCapabilities,
}

impl Grant {
    pub fn fs_scope(&self, scope: FsScope) -> Option<&FsScopeGrant> {
        self.fs.iter().find(|grant| grant.scope == scope)
    }

    pub fn allows_fs_write(&self, scope: FsScope) -> bool {
        self.fs_scope(scope)
            .is_some_and(|grant| grant.mode == FsMode::Rw)
    }

    pub fn mcp_grant(&self, alias: &str) -> Option<&McpGrant> {
        self.mcp.iter().find(|grant| grant.alias == alias)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FsScopeGrant {
    pub scope: FsScope,
    pub mode: FsMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_files: Option<u64>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum FsScope {
    Workspace,
    ModuleData,
    Input,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FsMode {
    Ro,
    Rw,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetGrant {
    #[serde(default)]
    pub allow: Vec<HostPattern>,
    #[serde(default)]
    pub credentials: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_requests_per_invocation: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes_per_invocation: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostPattern(pub String);

impl HostPattern {
    pub fn matches(&self, host: &str, port: u16) -> bool {
        let Some((pattern_host, pattern_port)) = self.0.rsplit_once(':') else {
            return false;
        };
        if pattern_port.parse::<u16>().ok() != Some(port) {
            return false;
        }
        if let Some(suffix) = pattern_host.strip_prefix("*.") {
            return host.ends_with(suffix) && host != suffix;
        }
        pattern_host.eq_ignore_ascii_case(host)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeGrant {
    pub max_cost_usd_per_invocation: f64,
    pub max_cost_usd_per_run: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub models: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BusGrant {
    #[serde(default)]
    pub produce: Vec<TopicPattern>,
    #[serde(default)]
    pub consume: Vec<TopicPattern>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TopicPattern(pub String);

impl TopicPattern {
    pub fn matches(&self, topic: &str) -> bool {
        if self.0 == topic {
            return true;
        }
        if let Some(prefix) = self.0.strip_suffix("/*") {
            return topic.starts_with(prefix) && topic[prefix.len()..].starts_with('/');
        }
        false
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FindingsGrant {
    pub create: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_per_invocation: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_severities: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactsGrant {
    pub write: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes_per_invocation: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FuzzGrant {
    #[serde(default)]
    pub engines: Vec<FuzzEngine>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_jobs_per_invocation: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cpu_seconds_per_invocation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_artifacts_bytes_per_invocation: Option<u64>,
    #[serde(default)]
    pub network: bool,
}

impl FuzzGrant {
    pub fn allows_engine(&self, engine: FuzzEngine) -> bool {
        self.engines.iter().any(|allowed| *allowed == engine)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FuzzEngine {
    CargoFuzz,
    Libfuzzer,
    Aflplusplus,
    Jazzer,
    GoFuzz,
    Atheris,
    JsFuzzilli,
    PropertyTests,
    Symcc,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecGrant {
    pub bin: String,
    #[serde(default)]
    pub argv_allow: Vec<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum InitCapabilities {
    FsRead,
}

impl Default for InitCapabilities {
    fn default() -> Self {
        Self::FsRead
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct McpGrant {
    pub alias: String,
    #[serde(default)]
    pub tools: Vec<String>,
    pub mode: McpGrantMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_calls_per_invocation: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cpu_seconds_per_invocation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes_per_invocation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_artifacts_bytes_per_invocation: Option<u64>,
    pub workspace: McpWorkspaceMode,
}

impl McpGrant {
    pub fn allows_tool(&self, tool: &str) -> bool {
        self.tools.iter().any(|allowed| allowed == tool)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum McpGrantMode {
    Shared,
    Dedicated,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum McpWorkspaceMode {
    ReadOnly,
    ScratchOnly,
    ReadWrite,
}

#[derive(Clone)]
pub struct InvocationAuthority {
    module_id: ModuleId,
    digest: Digest,
    run_id: RunId,
    invocation_id: InvocationId,
    epoch: u64,
    current_epoch: Arc<AtomicU64>,
    active: Arc<AtomicBool>,
    grant: Arc<Grant>,
    meter: Arc<Mutex<InvocationMeter>>,
}

impl InvocationAuthority {
    pub fn new(
        module_id: ModuleId,
        digest: Digest,
        run_id: RunId,
        invocation_id: InvocationId,
        current_epoch: Arc<AtomicU64>,
        grant: Arc<Grant>,
    ) -> Self {
        let epoch = current_epoch.load(Ordering::Acquire);
        Self {
            module_id,
            digest,
            run_id,
            invocation_id,
            epoch,
            current_epoch,
            active: Arc::new(AtomicBool::new(true)),
            grant,
            meter: Arc::new(Mutex::new(InvocationMeter::default())),
        }
    }

    pub fn module_id(&self) -> &ModuleId {
        &self.module_id
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    pub fn invocation_id(&self) -> &InvocationId {
        &self.invocation_id
    }

    pub fn grant(&self) -> &Grant {
        &self.grant
    }

    pub fn deactivate(&self) {
        self.active.store(false, Ordering::Release);
    }

    pub fn ensure_active(&self) -> Result<(), KwpError> {
        if self.active.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(KwpError::NoActiveInvocation)
        }
    }

    pub fn ensure_epoch_current(&self) -> Result<(), KwpError> {
        if self.current_epoch.load(Ordering::Acquire) == self.epoch {
            Ok(())
        } else {
            Err(KwpError::EpochStale)
        }
    }

    /// Rejects a brokered request whose `invocationId` does not match this authority.
    pub fn ensure_invocation_id(&self, id: &InvocationId) -> Result<(), KwpError> {
        if *id == self.invocation_id {
            Ok(())
        } else {
            Err(KwpError::NoActiveInvocation)
        }
    }

    pub async fn computed_cost_usd(&self) -> f64 {
        self.meter.lock().await.runtime_cost_usd
    }

    async fn add_runtime_cost(&self, cost: f64) {
        self.meter.lock().await.runtime_cost_usd += cost;
    }

    async fn reserve_fs_access(
        &self,
        grant: &FsScopeGrant,
        path: &str,
        bytes: u64,
    ) -> Result<(), KwpError> {
        let mut meter = self.meter.lock().await;
        reserve_fs_access_in_meter(&mut meter.fs, grant, path, bytes)
    }

    async fn reserve_net_request(&self, grant: &NetGrant, request: &NetFetchRequest) -> Result<Option<u64>, KwpError> {
        let mut meter = self.meter.lock().await;
        reserve_net_request_in_meter(&mut meter.net, grant, request)
    }

    async fn reserve_net_response(&self, grant: &NetGrant, result: &NetFetchResult) -> Result<(), KwpError> {
        let mut meter = self.meter.lock().await;
        reserve_net_response_in_meter(&mut meter.net, grant, result)
    }

    async fn reserve_mcp_call(&self, grant: &McpGrant, limits: &McpCallLimits) -> Result<(), KwpError> {
        let mut meter = self.meter.lock().await;
        meter.mcp_calls += 1;
        check_count(meter.mcp_calls, grant.max_calls_per_invocation, "mcp.calls")?;
        check_u64(limits.cpu_seconds, grant.max_cpu_seconds_per_invocation, "mcp.cpu_seconds")?;
        check_u64(limits.artifact_bytes, grant.max_artifacts_bytes_per_invocation, "mcp.artifact_bytes")?;
        Ok(())
    }

    async fn reserve_fuzz_job(&self, grant: &FuzzGrant, request: &FuzzRunRequest) -> Result<(), KwpError> {
        let mut meter = self.meter.lock().await;
        meter.fuzz_jobs += 1;
        check_count(meter.fuzz_jobs, grant.max_jobs_per_invocation, "fuzz.jobs")?;
        check_u64(request.limits.cpu_seconds, grant.max_cpu_seconds_per_invocation, "fuzz.cpu_seconds")?;
        check_u64(
            request.limits.artifact_bytes,
            grant.max_artifacts_bytes_per_invocation,
            "fuzz.artifact_bytes",
        )?;
        Ok(())
    }
}

#[derive(Default)]
struct InvocationMeter {
    runtime_cost_usd: f64,
    fs: FsAccessMeter,
    net: NetAccessMeter,
    mcp_calls: u32,
    fuzz_jobs: u32,
}

#[derive(Default)]
struct FsAccessMeter {
    bytes_by_scope: BTreeMap<FsScope, u64>,
    files: BTreeSet<(FsScope, String)>,
}

fn reserve_fs_access_in_meter(meter: &mut FsAccessMeter, grant: &FsScopeGrant, path: &str, bytes: u64) -> Result<(), KwpError> {
    let used_bytes = meter.bytes_by_scope.entry(grant.scope).or_default();
    *used_bytes = used_bytes
        .checked_add(bytes)
        .ok_or_else(|| KwpError::quota("fs.bytes"))?;
    check_u64(Some(*used_bytes), grant.max_bytes, "fs.bytes")?;
    reserve_fs_file(&mut meter.files, grant, path)
}

fn reserve_fs_file(
    files: &mut BTreeSet<(FsScope, String)>,
    grant: &FsScopeGrant,
    path: &str,
) -> Result<(), KwpError> {
    files.insert((grant.scope, path.to_string()));
    let used_files = files
        .iter()
        .filter(|(scope, _)| *scope == grant.scope)
        .count() as u64;
    check_u64(Some(used_files), grant.max_files, "fs.files")
}

#[derive(Default)]
struct NetAccessMeter {
    requests: u32,
    bytes: u64,
}

fn reserve_net_request_in_meter(meter: &mut NetAccessMeter, grant: &NetGrant, request: &NetFetchRequest) -> Result<Option<u64>, KwpError> {
    meter.requests = meter.requests.saturating_add(1);
    check_count(meter.requests, grant.max_requests_per_invocation, "net.requests")?;
    let request_bytes = net_request_body_len(request)?;
    reserve_net_bytes_in_meter(meter, grant, request_bytes)?;
    Ok(remaining_net_bytes(meter, grant))
}

fn reserve_net_response_in_meter(meter: &mut NetAccessMeter, grant: &NetGrant, result: &NetFetchResult) -> Result<(), KwpError> {
    reserve_net_bytes_in_meter(meter, grant, net_result_body_len(result)?)
}

fn reserve_net_bytes_in_meter(meter: &mut NetAccessMeter, grant: &NetGrant, bytes: u64) -> Result<(), KwpError> {
    meter.bytes = meter
        .bytes
        .checked_add(bytes)
        .ok_or_else(|| KwpError::quota("net.bytes"))?;
    check_u64(Some(meter.bytes), grant.max_bytes_per_invocation, "net.bytes")
}

fn remaining_net_bytes(meter: &NetAccessMeter, grant: &NetGrant) -> Option<u64> {
    grant
        .max_bytes_per_invocation
        .map(|max| max.saturating_sub(meter.bytes))
}

fn check_count(used: u32, max: Option<u32>, resource: &str) -> Result<(), KwpError> {
    if max.is_some_and(|max| used > max) {
        Err(KwpError::quota(resource))
    } else {
        Ok(())
    }
}

fn check_u64(requested: Option<u64>, max: Option<u64>, resource: &str) -> Result<(), KwpError> {
    match (requested, max) {
        (Some(requested), Some(max)) if requested > max => Err(KwpError::quota(resource)),
        _ => Ok(()),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactRef {
    pub path: String,
    pub media_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

pub fn validate_relative_path(path: &str) -> Result<(), PathValidationError> {
    if path.is_empty() || path.starts_with('/') || path.starts_with('\\') {
        return Err(PathValidationError);
    }
    if path
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == ".." || segment.contains('\\'))
    {
        return Err(PathValidationError);
    }
    Ok(())
}

pub fn validate_artifact_refs(artifacts: &[ArtifactRef]) -> Result<(), KwpError> {
    for artifact in artifacts {
        validate_relative_path(&artifact.path).map_err(|_| KwpError::denied("artifact.path"))?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathValidationError;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutorTier {
    Node,
    Wasm,
    Container,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkerBundle {
    pub specifier: String,
    pub module_id: ModuleId,
    pub module_root: PathBuf,
    pub entry: String,
    pub tier: ExecutorTier,
    pub digest: Digest,
    pub descriptor_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedWorkerBundle {
    pub specifier: String,
    pub module_root: PathBuf,
    pub entry: String,
    pub tier: ExecutorTier,
    pub digest: Digest,
}

impl ResolvedWorkerBundle {
    pub fn with_identity(&self, module_id: ModuleId, descriptor_hash: String) -> WorkerBundle {
        WorkerBundle {
            specifier: self.specifier.clone(),
            module_id,
            module_root: self.module_root.clone(),
            entry: self.entry.clone(),
            tier: self.tier,
            digest: self.digest.clone(),
            descriptor_hash,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LockfileEntry {
    pub module_id: ModuleId,
    pub digest: Digest,
    pub version: String,
    pub descriptor_hash: String,
    pub grant: Grant,
    #[serde(default)]
    pub signature_chain: Vec<String>,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KuzushiLockfile {
    #[serde(default)]
    pub modules: BTreeMap<String, LockfileEntry>,
}

impl KuzushiLockfile {
    pub fn entry_for_digest(&self, digest: &Digest) -> Option<&LockfileEntry> {
        self.modules.get(&digest.0)
    }

    pub fn read_json(path: impl AsRef<Path>) -> Result<Self, TrustError> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|error| TrustError::LockfileIo {
            path: path.to_path_buf(),
            error: error.to_string(),
        })?;
        let lockfile: Self = serde_json::from_slice(&bytes).map_err(|error| TrustError::LockfileParse {
            path: path.to_path_buf(),
            error: error.to_string(),
        })?;
        lockfile.validate_keys()?;
        Ok(lockfile)
    }

    pub fn read_json_or_default(path: impl AsRef<Path>) -> Result<Self, TrustError> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::default());
        }
        Self::read_json(path)
    }

    pub fn write_json(&self, path: impl AsRef<Path>) -> Result<(), TrustError> {
        self.validate_keys()?;
        let path = path.as_ref();
        let bytes = serde_json::to_vec_pretty(self).map_err(|error| TrustError::LockfileSerialize(error.to_string()))?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| TrustError::LockfileIo {
                path: parent.to_path_buf(),
                error: error.to_string(),
            })?;
        }
        fs::write(path, bytes).map_err(|error| TrustError::LockfileIo {
            path: path.to_path_buf(),
            error: error.to_string(),
        })
    }

    pub fn approve(&mut self, entry: LockfileEntry) -> Result<(), TrustError> {
        if entry.digest.0.trim().is_empty() {
            return Err(TrustError::LockfileInvalid("module digest must not be empty".to_string()));
        }
        self.modules.insert(entry.digest.0.clone(), entry);
        self.validate_keys()
    }

    fn validate_keys(&self) -> Result<(), TrustError> {
        for (digest, entry) in &self.modules {
            if digest != &entry.digest.0 {
                return Err(TrustError::LockfileDigestKeyMismatch {
                    key: digest.clone(),
                    entry_digest: entry.digest.0.clone(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedModule {
    pub module_id: ModuleId,
    pub digest: Digest,
    pub descriptor_hash: String,
    pub module_root: PathBuf,
    pub entry: String,
    pub tier: ExecutorTier,
    pub grant: Arc<Grant>,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum TrustError {
    #[error("module digest is not approved in kuzushi.lock")]
    NotInLockfile,
    #[error("module approval has been revoked")]
    Revoked,
    #[error("bad signature chain")]
    BadSignature,
    #[error("resolved module id differs from lockfile entry")]
    ModuleIdMismatch,
    #[error("resolved descriptor hash differs from lockfile entry")]
    DescriptorHashMismatch,
    #[error("lockfile digest key {key:?} differs from entry digest {entry_digest:?}")]
    LockfileDigestKeyMismatch { key: String, entry_digest: String },
    #[error("invalid lockfile: {0}")]
    LockfileInvalid(String),
    #[error("could not read or write lockfile {path}: {error}")]
    LockfileIo { path: PathBuf, error: String },
    #[error("could not parse lockfile {path}: {error}")]
    LockfileParse { path: PathBuf, error: String },
    #[error("could not serialize lockfile: {0}")]
    LockfileSerialize(String),
    #[error("unsupported worker bundle specifier: {0}")]
    UnsupportedSpecifier(String),
    #[error("worker bundle path is invalid: {0}")]
    BundlePathInvalid(String),
    #[error("worker bundle contains a symlink: {0}")]
    BundleSymlink(PathBuf),
    #[error("could not hash worker bundle {path}: {error}")]
    BundleIo { path: PathBuf, error: String },
    #[error("resolver failed: {0}")]
    Resolver(String),
}

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest(format!("sha256:{}", sha256_hex(bytes)))
}

pub fn descriptor_hash_from_value(value: &Value) -> Result<String, TrustError> {
    let bytes = serde_json::to_vec(value).map_err(|error| TrustError::LockfileInvalid(error.to_string()))?;
    Ok(format!("sha256:{}", sha256_hex(&bytes)))
}

pub fn resolve_file_worker_bundle(specifier: &str) -> Result<ResolvedWorkerBundle, TrustError> {
    let path = local_bundle_path(specifier)?;
    let canonical = fs::canonicalize(&path).map_err(|error| TrustError::BundleIo {
        path: path.clone(),
        error: error.to_string(),
    })?;
    let metadata = fs::symlink_metadata(&canonical).map_err(|error| TrustError::BundleIo {
        path: canonical.clone(),
        error: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() {
        return Err(TrustError::BundleSymlink(canonical));
    }
    if metadata.is_file() {
        return resolved_file_bundle(specifier, canonical);
    }
    if metadata.is_dir() {
        return resolved_directory_bundle(specifier, canonical);
    }
    Err(TrustError::BundlePathInvalid(format!(
        "{} is neither a regular file nor a directory",
        canonical.display()
    )))
}

fn local_bundle_path(specifier: &str) -> Result<PathBuf, TrustError> {
    if let Some(raw) = specifier.strip_prefix("file://") {
        return percent_decode_file_path(raw);
    }
    let path = PathBuf::from(specifier);
    if path.is_absolute() || specifier.starts_with("./") || specifier.starts_with("../") {
        return Ok(path);
    }
    Err(TrustError::UnsupportedSpecifier(specifier.to_string()))
}

fn percent_decode_file_path(raw: &str) -> Result<PathBuf, TrustError> {
    let mut bytes = Vec::with_capacity(raw.len());
    let mut iter = raw.as_bytes().iter().copied();
    while let Some(byte) = iter.next() {
        if byte != b'%' {
            bytes.push(byte);
            continue;
        }
        let Some(high) = iter.next() else {
            return Err(TrustError::BundlePathInvalid(raw.to_string()));
        };
        let Some(low) = iter.next() else {
            return Err(TrustError::BundlePathInvalid(raw.to_string()));
        };
        let decoded = (hex_value(high)? << 4) | hex_value(low)?;
        bytes.push(decoded);
    }
    String::from_utf8(bytes)
        .map(PathBuf::from)
        .map_err(|error| TrustError::BundlePathInvalid(error.to_string()))
}

fn hex_value(byte: u8) -> Result<u8, TrustError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(TrustError::BundlePathInvalid(format!(
            "invalid percent-escape byte 0x{byte:02x}"
        ))),
    }
}

fn resolved_file_bundle(specifier: &str, file: PathBuf) -> Result<ResolvedWorkerBundle, TrustError> {
    let root = file
        .parent()
        .ok_or_else(|| TrustError::BundlePathInvalid(format!("{} has no parent", file.display())))?
        .to_path_buf();
    let entry = file
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| TrustError::BundlePathInvalid(format!("{} has no UTF-8 file name", file.display())))?
        .to_string();
    let digest = hash_file_bundle(&root, &file)?;
    Ok(ResolvedWorkerBundle {
        specifier: specifier.to_string(),
        module_root: root,
        entry,
        tier: ExecutorTier::Node,
        digest,
    })
}

fn resolved_directory_bundle(specifier: &str, root: PathBuf) -> Result<ResolvedWorkerBundle, TrustError> {
    let digest = hash_directory_bundle(&root)?;
    Ok(ResolvedWorkerBundle {
        specifier: specifier.to_string(),
        module_root: root,
        entry: ".".to_string(),
        tier: ExecutorTier::Node,
        digest,
    })
}

fn hash_file_bundle(root: &Path, file: &Path) -> Result<Digest, TrustError> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"kwp-file-bundle-v1\0");
    hash_one_bundle_file(root, file, &mut hasher)?;
    Ok(Digest(format!("sha256:{}", sha256_hasher_hex(hasher))))
}

fn hash_directory_bundle(root: &Path) -> Result<Digest, TrustError> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"kwp-directory-bundle-v1\0");
    hash_directory_entries(root, root, &mut hasher)?;
    Ok(Digest(format!("sha256:{}", sha256_hasher_hex(hasher))))
}

fn hash_directory_entries(root: &Path, dir: &Path, hasher: &mut sha2::Sha256) -> Result<(), TrustError> {
    let mut entries = fs::read_dir(dir)
        .map_err(|error| TrustError::BundleIo {
            path: dir.to_path_buf(),
            error: error.to_string(),
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| TrustError::BundleIo {
            path: dir.to_path_buf(),
            error: error.to_string(),
        })?;
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| TrustError::BundleIo {
            path: path.clone(),
            error: error.to_string(),
        })?;
        if metadata.file_type().is_symlink() {
            return Err(TrustError::BundleSymlink(path));
        }
        if metadata.is_dir() {
            hash_directory_entries(root, &path, hasher)?;
        } else if metadata.is_file() {
            hash_one_bundle_file(root, &path, hasher)?;
        }
    }
    Ok(())
}

fn hash_one_bundle_file(root: &Path, file: &Path, hasher: &mut sha2::Sha256) -> Result<(), TrustError> {
    let relative = file.strip_prefix(root).map_err(|error| TrustError::BundlePathInvalid(error.to_string()))?;
    let relative = relative
        .to_str()
        .ok_or_else(|| TrustError::BundlePathInvalid(format!("{} is not UTF-8", relative.display())))?;
    let bytes = fs::read(file).map_err(|error| TrustError::BundleIo {
        path: file.to_path_buf(),
        error: error.to_string(),
    })?;
    hasher.update(relative.as_bytes());
    hasher.update(b"\0");
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(b"\0");
    hasher.update(&bytes);
    hasher.update(b"\0");
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};

    let digest = Sha256::digest(bytes);
    digest_hex(digest.as_slice())
}

fn sha256_hasher_hex(hasher: sha2::Sha256) -> String {
    use sha2::Digest as _;

    let digest = hasher.finalize();
    digest_hex(digest.as_slice())
}

fn digest_hex(digest: &[u8]) -> String {
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(nibble_to_hex(byte >> 4));
        out.push(nibble_to_hex(byte & 0x0f));
    }
    out
}

fn nibble_to_hex(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + (nibble - 10)) as char,
        _ => unreachable!("nibble is always <= 15"),
    }
}

#[async_trait]
pub trait BundleResolver: Send + Sync {
    async fn resolve(&self, specifier: &str) -> Result<WorkerBundle, TrustError>;
}

pub trait SignatureVerifier: Send + Sync {
    fn verify_chain(&self, entry: &LockfileEntry, bundle: &WorkerBundle) -> bool;
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureAlgorithm {
    #[default]
    Ed25519,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct SignatureTrustKey {
    pub key_id: String,
    pub algorithm: SignatureAlgorithm,
    pub public_key: String,
}

impl SignatureTrustKey {
    pub fn validate(&self) -> Result<(), SignatureVerificationError> {
        if self.key_id.trim().is_empty() || self.key_id.contains(':') {
            return Err(SignatureVerificationError::InvalidKeyId);
        }
        match self.algorithm {
            SignatureAlgorithm::Ed25519 => decode_ed25519_public_key(self).map(|_| ()),
        }
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum SignatureVerificationError {
    #[error("signatureChain is present but no trusted signature keys are configured")]
    MissingTrustedKeys,
    #[error("signatureChain entry must have form ed25519:v1:<keyId>:<base64Signature>")]
    BadEntryFormat,
    #[error("signatureChain key id is invalid")]
    InvalidKeyId,
    #[error("signatureChain references unknown key id {0:?}")]
    UnknownKey(String),
    #[error("signatureChain public key is invalid")]
    InvalidPublicKey,
    #[error("signatureChain signature is invalid")]
    InvalidSignature,
    #[error("could not build signature payload: {0}")]
    Payload(String),
}

#[derive(Clone, Debug, Default)]
pub struct ConfiguredSignatureVerifier {
    keys: BTreeMap<String, SignatureTrustKey>,
}

impl ConfiguredSignatureVerifier {
    pub fn new(keys: Vec<SignatureTrustKey>) -> Self {
        Self {
            keys: keys
                .into_iter()
                .map(|key| (key.key_id.clone(), key))
                .collect(),
        }
    }

    pub fn verify_lockfile_entry(&self, entry: &LockfileEntry) -> Result<(), SignatureVerificationError> {
        if entry.signature_chain.is_empty() {
            return Ok(());
        }
        if self.keys.is_empty() {
            return Err(SignatureVerificationError::MissingTrustedKeys);
        }
        let payload = signature_payload_bytes(entry)?;
        for signature in &entry.signature_chain {
            self.verify_signature_entry(signature, &payload)?;
        }
        Ok(())
    }

    fn verify_signature_entry(&self, raw: &str, payload: &[u8]) -> Result<(), SignatureVerificationError> {
        let entry = ParsedSignatureChainEntry::parse(raw)?;
        let key = self
            .keys
            .get(entry.key_id)
            .ok_or_else(|| SignatureVerificationError::UnknownKey(entry.key_id.to_string()))?;
        match key.algorithm {
            SignatureAlgorithm::Ed25519 => verify_ed25519_signature(key, entry.signature, payload),
        }
    }
}

impl SignatureVerifier for ConfiguredSignatureVerifier {
    fn verify_chain(&self, entry: &LockfileEntry, bundle: &WorkerBundle) -> bool {
        if entry.module_id != bundle.module_id
            || entry.digest != bundle.digest
            || entry.descriptor_hash != bundle.descriptor_hash
        {
            return false;
        }
        self.verify_lockfile_entry(entry).is_ok()
    }
}

struct ParsedSignatureChainEntry<'a> {
    key_id: &'a str,
    signature: &'a str,
}

impl<'a> ParsedSignatureChainEntry<'a> {
    fn parse(raw: &'a str) -> Result<Self, SignatureVerificationError> {
        let mut parts = raw.splitn(4, ':');
        let algorithm = parts.next();
        let version = parts.next();
        let key_id = parts.next();
        let signature = parts.next();
        let (Some("ed25519"), Some("v1"), Some(key_id), Some(signature)) =
            (algorithm, version, key_id, signature)
        else {
            return Err(SignatureVerificationError::BadEntryFormat);
        };
        if key_id.trim().is_empty() || key_id.contains(':') || signature.trim().is_empty() || signature.contains(':') {
            return Err(SignatureVerificationError::BadEntryFormat);
        }
        Ok(Self { key_id, signature })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignaturePayload<'a> {
    domain: &'static str,
    module_id: &'a ModuleId,
    digest: &'a Digest,
    descriptor_hash: &'a str,
    version: &'a str,
}

fn signature_payload_bytes(entry: &LockfileEntry) -> Result<Vec<u8>, SignatureVerificationError> {
    serde_json::to_vec(&SignaturePayload {
        domain: "kuzushi-kwp-signature-v1",
        module_id: &entry.module_id,
        digest: &entry.digest,
        descriptor_hash: &entry.descriptor_hash,
        version: &entry.version,
    })
    .map_err(|error| SignatureVerificationError::Payload(error.to_string()))
}

fn verify_ed25519_signature(
    key: &SignatureTrustKey,
    signature: &str,
    payload: &[u8],
) -> Result<(), SignatureVerificationError> {
    let verifying_key = decode_ed25519_public_key(key)?;
    let signature = BASE64
        .decode(signature.as_bytes())
        .map_err(|_| SignatureVerificationError::InvalidSignature)?;
    let signature = ed25519_dalek::Signature::from_slice(&signature)
        .map_err(|_| SignatureVerificationError::InvalidSignature)?;
    ed25519_dalek::Verifier::verify(&verifying_key, payload, &signature)
        .map_err(|_| SignatureVerificationError::InvalidSignature)
}

fn decode_ed25519_public_key(key: &SignatureTrustKey) -> Result<ed25519_dalek::VerifyingKey, SignatureVerificationError> {
    let public_key = BASE64
        .decode(key.public_key.as_bytes())
        .map_err(|_| SignatureVerificationError::InvalidPublicKey)?;
    let public_key: [u8; 32] = public_key
        .as_slice()
        .try_into()
        .map_err(|_| SignatureVerificationError::InvalidPublicKey)?;
    ed25519_dalek::VerifyingKey::from_bytes(&public_key)
        .map_err(|_| SignatureVerificationError::InvalidPublicKey)
}

pub struct LockfileTrustVerifier {
    lockfile: Arc<KuzushiLockfile>,
    resolver: Arc<dyn BundleResolver>,
    signatures: Arc<dyn SignatureVerifier>,
}

impl LockfileTrustVerifier {
    pub fn new(lockfile: Arc<KuzushiLockfile>, resolver: Arc<dyn BundleResolver>, signatures: Arc<dyn SignatureVerifier>) -> Self {
        Self { lockfile, resolver, signatures }
    }

    pub async fn verify(&self, specifier: &str) -> Result<VerifiedModule, TrustError> {
        let bundle = self.resolver.resolve(specifier).await?;
        let entry = self
            .lockfile
            .entry_for_digest(&bundle.digest)
            .ok_or(TrustError::NotInLockfile)?;
        if entry.revoked {
            return Err(TrustError::Revoked);
        }
        if entry.module_id != bundle.module_id {
            return Err(TrustError::ModuleIdMismatch);
        }
        if entry.descriptor_hash != bundle.descriptor_hash {
            return Err(TrustError::DescriptorHashMismatch);
        }
        if !self.signatures.verify_chain(entry, &bundle) {
            return Err(TrustError::BadSignature);
        }
        Ok(VerifiedModule {
            module_id: bundle.module_id,
            digest: bundle.digest,
            descriptor_hash: bundle.descriptor_hash,
            module_root: bundle.module_root,
            entry: bundle.entry,
            tier: bundle.tier,
            grant: Arc::new(entry.grant.clone()),
        })
    }
}

#[async_trait]
pub trait FsBackend: Send + Sync {
    async fn read(&self, scope: FsScope, path: &str, offset: u64, length: Option<u64>) -> Result<FsReadResult, KwpError>;
    async fn write(&self, scope: FsScope, path: &str, data: Vec<u8>, append: bool) -> Result<u64, KwpError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsReadResult {
    pub data: Vec<u8>,
    pub eof: bool,
}

#[async_trait]
pub trait NetBackend: Send + Sync {
    async fn fetch(&self, request: NetFetchRequest) -> Result<NetFetchResult, KwpError>;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetFetchRequest {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_artifact_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_media_type: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetFetchResult {
    pub status: u16,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<ArtifactRef>,
}

#[async_trait]
pub trait RuntimeBackend: Send + Sync {
    async fn query(&self, request: RuntimeQueryRequest) -> Result<RuntimeQueryResult, KwpError>;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeQueryRequest {
    pub messages: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,
    pub max_tokens: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_preferences: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeQueryResult {
    pub completion: Value,
    pub cost_usd: f64,
}

#[async_trait]
pub trait BusBackend: Send + Sync {
    async fn publish(&self, origin: EventOrigin, topic: String, payload: Value) -> Result<(), KwpError>;
}

#[async_trait]
pub trait FindingBackend: Send + Sync {
    async fn create(&self, origin: EventOrigin, findings: Vec<Value>) -> Result<FindingsCreateResult, KwpError>;
}

#[async_trait]
pub trait ArtifactBackend: Send + Sync {
    async fn record(&self, origin: EventOrigin, artifacts: Vec<ArtifactRef>) -> Result<Vec<ArtifactRef>, KwpError>;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EventOrigin {
    pub module_id: ModuleId,
    pub digest: Digest,
    pub invocation_id: InvocationId,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FindingsCreateResult {
    pub created: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpToolDescriptor {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpCatalogEntry {
    pub alias: String,
    pub descriptor_hash: String,
    pub tools: BTreeMap<String, McpToolDescriptor>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpCatalog {
    entries: BTreeMap<String, McpCatalogEntry>,
}

impl McpCatalog {
    pub fn insert(&mut self, entry: McpCatalogEntry) {
        self.entries.insert(entry.alias.clone(), entry);
    }

    pub fn get(&self, alias: &str) -> Option<&McpCatalogEntry> {
        self.entries.get(alias)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct McpSessionKey {
    pub alias: String,
    pub module_id: ModuleId,
    pub module_digest: Digest,
    pub run_id: RunId,
    pub invocation_id: InvocationId,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpCallLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_bytes: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpCallRequest {
    pub invocation_id: InvocationId,
    pub alias: String,
    pub tool: String,
    #[serde(default)]
    pub arguments: Value,
    #[serde(default)]
    pub limits: McpCallLimits,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpCallResult {
    #[serde(default)]
    pub structured_content: Value,
    #[serde(default)]
    pub artifacts: Vec<ArtifactRef>,
}

#[async_trait]
pub trait McpBackend: Send + Sync {
    async fn call(&self, session: McpSessionKey, request: McpCallRequest) -> Result<McpCallResult, KwpError>;
}

#[derive(Clone, Debug, Default)]
pub struct HostMcpBroker {
    catalog: McpCatalog,
    mounts: BTreeMap<String, StdioMcpMount>,
}

impl HostMcpBroker {
    pub fn from_config(
        config: &crate::config::V2Config,
        workspace: Option<&crate::workspace::WorkspaceTarget>,
    ) -> Self {
        let mut broker = Self::default();
        for mount in &config.operator.mcp_mounts {
            broker.insert_mount(mount, workspace);
        }
        broker
    }

    pub fn catalog(&self) -> &McpCatalog {
        &self.catalog
    }

    pub fn call_blocking(
        &self,
        session: McpSessionKey,
        request: McpCallRequest,
    ) -> Result<McpCallResult, KwpError> {
        let mount = self
            .mounts
            .get(&request.alias)
            .ok_or_else(|| KwpError::denied("mcp.mount"))?;
        mount.call(session, request)
    }

    fn insert_mount(
        &mut self,
        config: &crate::config::McpMountConfig,
        workspace: Option<&crate::workspace::WorkspaceTarget>,
    ) {
        let mount = StdioMcpMount::from_config(config, workspace);
        self.catalog.insert(mount.catalog_entry());
        self.mounts.insert(mount.alias.clone(), mount);
    }
}

#[async_trait]
impl McpBackend for HostMcpBroker {
    async fn call(
        &self,
        session: McpSessionKey,
        request: McpCallRequest,
    ) -> Result<McpCallResult, KwpError> {
        self.call_blocking(session, request)
    }
}

#[derive(Clone, Debug)]
struct StdioMcpMount {
    alias: String,
    command: Vec<String>,
    descriptor_hash: String,
    tools: BTreeMap<String, McpToolDescriptor>,
    cwd: PathBuf,
}

impl StdioMcpMount {
    fn from_config(
        config: &crate::config::McpMountConfig,
        workspace: Option<&crate::workspace::WorkspaceTarget>,
    ) -> Self {
        Self {
            alias: config.alias.clone(),
            command: config.command.clone(),
            descriptor_hash: config.descriptor_hash.clone(),
            tools: mcp_tools_from_config(&config.tools),
            cwd: mcp_mount_cwd(workspace),
        }
    }

    fn catalog_entry(&self) -> McpCatalogEntry {
        McpCatalogEntry {
            alias: self.alias.clone(),
            descriptor_hash: self.descriptor_hash.clone(),
            tools: self.tools.clone(),
        }
    }

    fn call(
        &self,
        session: McpSessionKey,
        request: McpCallRequest,
    ) -> Result<McpCallResult, KwpError> {
        let mut client = McpStdioClient::spawn(self, &session)?;
        let tools = client.list_tools()?;
        ensure_mcp_descriptor_matches(&self.descriptor_hash, &tools)?;
        client.call_tool(&request.tool, request.arguments)
    }
}

fn mcp_mount_cwd(workspace: Option<&crate::workspace::WorkspaceTarget>) -> PathBuf {
    workspace
        .map(|workspace| workspace.root().to_path_buf())
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
}

fn mcp_tools_from_config(
    tools: &[crate::config::McpMountToolConfig],
) -> BTreeMap<String, McpToolDescriptor> {
    tools
        .iter()
        .map(|tool| {
            (
                tool.name.clone(),
                McpToolDescriptor {
                    name: tool.name.clone(),
                    description: tool.description.clone(),
                    input_schema: tool.input_schema.clone(),
                    output_schema: tool.output_schema.clone(),
                },
            )
        })
        .collect()
}

fn ensure_mcp_descriptor_matches(
    expected_hash: &str,
    tools: &BTreeMap<String, McpToolDescriptor>,
) -> Result<(), KwpError> {
    let actual = mcp_descriptor_hash_from_tools(tools)?;
    if actual == expected_hash {
        Ok(())
    } else {
        Err(KwpError::denied("mcp.descriptor"))
    }
}

pub fn mcp_descriptor_hash_from_tools(
    tools: &BTreeMap<String, McpToolDescriptor>,
) -> Result<String, KwpError> {
    descriptor_hash_from_value(&serde_json::json!({ "tools": tools }))
        .map_err(|error| KwpError::Internal(error.to_string()))
}

struct McpStdioClient {
    alias: String,
    child: Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    next_id: u64,
}

impl McpStdioClient {
    fn spawn(mount: &StdioMcpMount, session: &McpSessionKey) -> Result<Self, KwpError> {
        let mut child = spawn_mcp_process(mount, session)?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| KwpError::Internal("MCP server stdin unavailable".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| KwpError::Internal("MCP server stdout unavailable".to_string()))?;
        tag_mcp_stderr(&mut child, &mount.alias);
        let mut client = Self {
            alias: mount.alias.clone(),
            child,
            stdin,
            stdout: BufReader::new(stdout),
            next_id: 1,
        };
        client.initialize()?;
        Ok(client)
    }

    fn initialize(&mut self) -> Result<(), KwpError> {
        self.request(
            "initialize",
            serde_json::json!({
                "protocolVersion": "2024-11-05",
                "clientInfo": { "name": "kuzushi-kwp-host", "version": KWP_VERSION },
                "capabilities": {},
            }),
        )
        .map(|_| ())
    }

    fn list_tools(&mut self) -> Result<BTreeMap<String, McpToolDescriptor>, KwpError> {
        let result = self.request("tools/list", Value::Object(serde_json::Map::new()))?;
        mcp_tools_from_list_result(&result)
    }

    fn call_tool(&mut self, name: &str, arguments: Value) -> Result<McpCallResult, KwpError> {
        let result = self.request(
            "tools/call",
            serde_json::json!({ "name": name, "arguments": arguments }),
        )?;
        mcp_call_result_from_tool_result(result)
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value, KwpError> {
        let id = self.next_id;
        self.next_id += 1;
        write_mcp_rpc(&mut self.stdin, id, method, params)?;
        let response = self.read_response_with_id(id)?;
        mcp_result_from_response(method, response)
    }

    fn read_response_with_id(&mut self, expected_id: u64) -> Result<Value, KwpError> {
        let mut line = String::new();
        loop {
            line.clear();
            let n = self
                .stdout
                .read_line(&mut line)
                .map_err(|error| KwpError::Internal(format!("MCP {} stdout read failed: {error}", self.alias)))?;
            if n == 0 {
                return Err(KwpError::Internal(format!("MCP {} closed stdout", self.alias)));
            }
            if let Some(response) = matching_mcp_response(&line, expected_id)? {
                return Ok(response);
            }
        }
    }
}

impl Drop for McpStdioClient {
    fn drop(&mut self) {
        let _ = write_mcp_rpc(&mut self.stdin, 999_999, "shutdown", Value::Null);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_mcp_process(
    mount: &StdioMcpMount,
    session: &McpSessionKey,
) -> Result<Child, KwpError> {
    let Some((program, args)) = mount.command.split_first() else {
        return Err(KwpError::BadRequest("MCP mount command omitted".to_string()));
    };
    let mut command = Command::new(program);
    command.args(args).current_dir(&mount.cwd);
    command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    sanitize_mcp_environment(&mut command, session);
    command
        .spawn()
        .map_err(|error| KwpError::Internal(format!("could not start MCP alias {}: {error}", mount.alias)))
}

fn sanitize_mcp_environment(command: &mut Command, session: &McpSessionKey) {
    let path = std::env::var_os("PATH");
    let tmpdir = std::env::var_os("TMPDIR");
    command.env_clear();
    if let Some(path) = path {
        command.env("PATH", path);
    }
    if let Some(tmpdir) = tmpdir {
        command.env("TMPDIR", tmpdir);
    }
    command.env("KUZUSHI_MCP_ALIAS", &session.alias);
    command.env("KUZUSHI_MCP_SESSION_ID", mcp_session_id(session));
    command.env("KUZUSHI_KWP_INVOCATION_ID", &session.invocation_id.0);
    command.env("KUZUSHI_KWP_MODULE_DIGEST", &session.module_digest.0);
}

fn mcp_session_id(session: &McpSessionKey) -> String {
    format!(
        "{}:{}:{}",
        session.alias, session.module_digest.0, session.invocation_id.0
    )
    .replace([':', '/', '\\'], "_")
}

fn tag_mcp_stderr(child: &mut Child, alias: &str) {
    let Some(stderr) = child.stderr.take() else {
        return;
    };
    let alias = alias.to_string();
    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            eprintln!("[kwp:mcp:{alias}:stderr] {line}");
        }
    });
}

fn write_mcp_rpc(
    writer: &mut impl Write,
    id: u64,
    method: &str,
    params: Value,
) -> Result<(), KwpError> {
    let mut line = serde_json::to_string(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    }))
    .map_err(|error| KwpError::Internal(error.to_string()))?;
    line.push('\n');
    writer
        .write_all(line.as_bytes())
        .map_err(|error| KwpError::Internal(format!("MCP stdin write failed: {error}")))?;
    writer
        .flush()
        .map_err(|error| KwpError::Internal(format!("MCP stdin flush failed: {error}")))
}

fn matching_mcp_response(line: &str, expected_id: u64) -> Result<Option<Value>, KwpError> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let response: Value = serde_json::from_str(trimmed)
        .map_err(|error| KwpError::Internal(format!("MCP sent invalid JSON: {error}")))?;
    let matches = response
        .get("id")
        .and_then(Value::as_u64)
        .is_some_and(|id| id == expected_id);
    Ok(matches.then_some(response))
}

fn mcp_result_from_response(method: &str, response: Value) -> Result<Value, KwpError> {
    if let Some(error) = response.get("error") {
        return Err(KwpError::Internal(format!(
            "MCP {method} error: {}",
            mcp_error_message(error)
        )));
    }
    Ok(response.get("result").cloned().unwrap_or(Value::Null))
}

fn mcp_error_message(error: &Value) -> String {
    error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("unknown MCP error")
        .to_string()
}

fn mcp_tools_from_list_result(
    result: &Value,
) -> Result<BTreeMap<String, McpToolDescriptor>, KwpError> {
    let tools = result
        .get("tools")
        .and_then(Value::as_array)
        .ok_or_else(|| KwpError::BadRequest("MCP tools/list omitted tools".to_string()))?;
    tools
        .iter()
        .map(mcp_tool_from_value)
        .map(|tool| tool.map(|tool| (tool.name.clone(), tool)))
        .collect()
}

fn mcp_tool_from_value(value: &Value) -> Result<McpToolDescriptor, KwpError> {
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| KwpError::BadRequest("MCP tool name omitted".to_string()))?;
    Ok(McpToolDescriptor {
        name: name.to_string(),
        description: mcp_tool_description(value),
        input_schema: mcp_tool_schema(value, "inputSchema", "input_schema"),
        output_schema: mcp_optional_tool_schema(value, "outputSchema", "output_schema"),
    })
}

fn mcp_tool_description(value: &Value) -> String {
    value
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn mcp_tool_schema(value: &Value, camel: &str, snake: &str) -> Value {
    value
        .get(camel)
        .or_else(|| value.get(snake))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({ "type": "object" }))
}

fn mcp_optional_tool_schema(value: &Value, camel: &str, snake: &str) -> Option<Value> {
    value.get(camel).or_else(|| value.get(snake)).cloned()
}

fn mcp_call_result_from_tool_result(result: Value) -> Result<McpCallResult, KwpError> {
    if result.get("isError").and_then(Value::as_bool) == Some(true) {
        return Err(KwpError::Internal(mcp_tool_error_detail(&result)));
    }
    Ok(McpCallResult {
        structured_content: mcp_structured_content(&result),
        artifacts: mcp_artifacts_from_result(&result)?,
    })
}

fn mcp_structured_content(result: &Value) -> Value {
    result
        .get("structuredContent")
        .or_else(|| result.get("structured_content"))
        .cloned()
        .unwrap_or_else(|| result.clone())
}

fn mcp_artifacts_from_result(result: &Value) -> Result<Vec<ArtifactRef>, KwpError> {
    let artifacts = result
        .pointer("/_kuzushi/artifacts")
        .or_else(|| result.get("artifacts"))
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    serde_json::from_value(artifacts).map_err(|error| KwpError::BadRequest(error.to_string()))
}

fn mcp_tool_error_detail(result: &Value) -> String {
    result
        .get("content")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("text"))
        .and_then(Value::as_str)
        .unwrap_or("MCP tool returned an error")
        .to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FuzzRunRequest {
    pub invocation_id: InvocationId,
    pub engine: FuzzEngine,
    pub target: FuzzTarget,
    #[serde(default)]
    pub inputs: BTreeMap<String, String>,
    #[serde(default)]
    pub limits: FuzzLimits,
    #[serde(default)]
    pub sandbox: FuzzSandbox,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FuzzTarget {
    pub language: String,
    pub project_path: String,
    pub harness_path: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FuzzLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_crashes: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FuzzSandbox {
    #[serde(default)]
    pub network: bool,
    #[serde(default = "default_true")]
    pub read_only_source: bool,
}

impl Default for FuzzSandbox {
    fn default() -> Self {
        Self { network: false, read_only_source: true }
    }
}

fn default_true() -> bool {
    true
}

fn validate_fuzz_request_paths(request: &FuzzRunRequest) -> Result<(), KwpError> {
    validate_relative_path(&request.target.project_path).map_err(|_| KwpError::denied("fuzz.projectPath"))?;
    validate_relative_path(&request.target.harness_path).map_err(|_| KwpError::denied("fuzz.harnessPath"))?;
    for (key, value) in &request.inputs {
        if is_path_like_fuzz_input(key) {
            validate_relative_path(value).map_err(|_| KwpError::denied("fuzz.inputPath"))?;
        }
    }
    Ok(())
}

fn is_path_like_fuzz_input(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.ends_with("path") || key.ends_with("dir") || key.ends_with("directory")
}

fn min_optional_u64(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FuzzRunResult {
    pub status: String,
    #[serde(default)]
    pub artifacts: Vec<ArtifactRef>,
    #[serde(default)]
    pub crashes: Vec<Value>,
}

#[async_trait]
pub trait FuzzBackend: Send + Sync {
    async fn run(&self, origin: EventOrigin, request: FuzzRunRequest) -> Result<FuzzRunResult, KwpError>;
}

#[derive(Clone, Debug, Default)]
pub struct HostFuzzExecutor {
    executors: Vec<FuzzExecutorMount>,
    workspace_root: Option<PathBuf>,
}

impl HostFuzzExecutor {
    pub fn from_config(
        config: &crate::config::V2Config,
        workspace: Option<&crate::workspace::WorkspaceTarget>,
    ) -> Self {
        Self {
            executors: config
                .operator
                .fuzz_executors
                .iter()
                .map(FuzzExecutorMount::from_config)
                .collect(),
            workspace_root: workspace.map(|workspace| workspace.root().to_path_buf()),
        }
    }

    pub fn run_blocking(
        &self,
        origin: EventOrigin,
        request: FuzzRunRequest,
    ) -> Result<FuzzRunResult, KwpError> {
        let mount = self
            .executors
            .iter()
            .find(|executor| executor.engine == request.engine)
            .ok_or_else(|| KwpError::denied("fuzz.executor"))?;
        let workspace_root = self
            .workspace_root
            .as_ref()
            .ok_or_else(|| KwpError::denied("workspace"))?;
        mount.run(workspace_root, origin, request)
    }
}

#[async_trait]
impl FuzzBackend for HostFuzzExecutor {
    async fn run(&self, origin: EventOrigin, request: FuzzRunRequest) -> Result<FuzzRunResult, KwpError> {
        self.run_blocking(origin, request)
    }
}

#[derive(Clone, Debug)]
struct FuzzExecutorMount {
    engine: FuzzEngine,
    command: Vec<String>,
    timeout_ms: Option<u64>,
}

impl FuzzExecutorMount {
    fn from_config(config: &crate::config::FuzzExecutorConfig) -> Self {
        Self {
            engine: config.engine,
            command: config.command.clone(),
            timeout_ms: config.timeout_ms,
        }
    }

    fn run(
        &self,
        workspace_root: &Path,
        origin: EventOrigin,
        request: FuzzRunRequest,
    ) -> Result<FuzzRunResult, KwpError> {
        let payload = fuzz_executor_payload(workspace_root, &origin, &request)?;
        let stdout = tempfile::NamedTempFile::new().map_err(|error| KwpError::Internal(error.to_string()))?;
        let stderr = tempfile::NamedTempFile::new().map_err(|error| KwpError::Internal(error.to_string()))?;
        let mut child = spawn_fuzz_process(self, workspace_root, &origin, &stdout, &stderr)?;
        write_fuzz_stdin(&mut child, &payload)?;
        let completed = wait_for_fuzz_process(&mut child, fuzz_timeout(self, &request))?;
        let stderr = fs::read_to_string(stderr.path()).unwrap_or_default();
        if !completed {
            return Ok(FuzzRunResult {
                status: "timeout".to_string(),
                artifacts: Vec::new(),
                crashes: Vec::new(),
            });
        }
        let output = fs::read_to_string(stdout.path()).map_err(|error| KwpError::Internal(error.to_string()))?;
        parse_fuzz_output(output, stderr)
    }
}

fn fuzz_executor_payload(
    workspace_root: &Path,
    origin: &EventOrigin,
    request: &FuzzRunRequest,
) -> Result<Value, KwpError> {
    let project_path = resolve_read_path(workspace_root, &request.target.project_path)?;
    let harness_path = resolve_read_path(workspace_root, &request.target.harness_path)?;
    Ok(serde_json::json!({
        "origin": origin,
        "workspaceRoot": workspace_root.display().to_string(),
        "projectPath": project_path.display().to_string(),
        "harnessPath": harness_path.display().to_string(),
        "network": request.sandbox.network,
        "request": request,
    }))
}

fn spawn_fuzz_process(
    mount: &FuzzExecutorMount,
    workspace_root: &Path,
    origin: &EventOrigin,
    stdout: &tempfile::NamedTempFile,
    stderr: &tempfile::NamedTempFile,
) -> Result<Child, KwpError> {
    let Some((program, args)) = mount.command.split_first() else {
        return Err(KwpError::BadRequest("fuzz executor command omitted".to_string()));
    };
    let mut command = Command::new(program);
    command.args(args).current_dir(workspace_root);
    command.stdin(Stdio::piped());
    command.stdout(stdout.reopen().map_err(|error| KwpError::Internal(error.to_string()))?);
    command.stderr(stderr.reopen().map_err(|error| KwpError::Internal(error.to_string()))?);
    sanitize_fuzz_environment(&mut command, origin);
    command
        .spawn()
        .map_err(|error| KwpError::Internal(format!("could not start fuzz executor: {error}")))
}

fn sanitize_fuzz_environment(command: &mut Command, origin: &EventOrigin) {
    let path = std::env::var_os("PATH");
    let tmpdir = std::env::var_os("TMPDIR");
    command.env_clear();
    if let Some(path) = path {
        command.env("PATH", path);
    }
    if let Some(tmpdir) = tmpdir {
        command.env("TMPDIR", tmpdir);
    }
    command.env("KUZUSHI_KWP_INVOCATION_ID", &origin.invocation_id.0);
    command.env("KUZUSHI_KWP_MODULE_DIGEST", &origin.digest.0);
}

fn write_fuzz_stdin(child: &mut Child, payload: &Value) -> Result<(), KwpError> {
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| KwpError::Internal("fuzz executor stdin unavailable".to_string()))?;
    serde_json::to_writer(&mut stdin, payload).map_err(|error| KwpError::Internal(error.to_string()))?;
    stdin
        .write_all(b"\n")
        .map_err(|error| KwpError::Internal(error.to_string()))
}

fn fuzz_timeout(mount: &FuzzExecutorMount, request: &FuzzRunRequest) -> Duration {
    let timeout_ms = request
        .limits
        .deadline_ms
        .or(mount.timeout_ms)
        .unwrap_or(60_000);
    Duration::from_millis(timeout_ms.max(1))
}

fn wait_for_fuzz_process(child: &mut Child, timeout: Duration) -> Result<bool, KwpError> {
    let start = Instant::now();
    loop {
        if child.try_wait().map_err(|error| KwpError::Internal(error.to_string()))?.is_some() {
            return Ok(true);
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn parse_fuzz_output(stdout: String, stderr: String) -> Result<FuzzRunResult, KwpError> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(FuzzRunResult {
            status: "completed".to_string(),
            artifacts: Vec::new(),
            crashes: Vec::new(),
        });
    }
    serde_json::from_str(trimmed)
        .map(normalize_fuzz_status)
        .map_err(|error| KwpError::Internal(format!("fuzz executor returned invalid JSON: {error}; stderr={stderr}")))
}

fn normalize_fuzz_status(mut result: FuzzRunResult) -> FuzzRunResult {
    if result.status.trim().is_empty() {
        result.status = "completed".to_string();
    }
    result
}

#[async_trait]
pub trait AuditSink: Send + Sync {
    async fn record(&self, record: AuditRecord);
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuditRecord {
    pub event: String,
    pub decision: AuditDecision,
    pub module_id: ModuleId,
    pub digest: Digest,
    pub invocation_id: InvocationId,
    #[serde(default)]
    pub detail: Value,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AuditDecision {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KwpAuditLogRecord {
    pub ts_ms: u64,
    pub run_id: RunId,
    pub invocation_id: InvocationId,
    pub module_id: ModuleId,
    pub digest: Digest,
    pub event: String,
    pub decision: AuditDecision,
    #[serde(default)]
    pub detail: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    pub hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KwpBusEvent {
    pub ts_ms: u64,
    pub run_id: RunId,
    pub invocation_id: InvocationId,
    pub module_id: ModuleId,
    pub digest: Digest,
    pub topic: String,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KwpAuditIntegrity {
    pub ok: bool,
    pub errors: Vec<KwpAuditIntegrityError>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KwpAuditIntegrityError {
    pub index: usize,
    pub field: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct KwpAuditLogBody {
    ts_ms: u64,
    run_id: RunId,
    invocation_id: InvocationId,
    module_id: ModuleId,
    digest: Digest,
    event: String,
    decision: AuditDecision,
    detail: Value,
    prev: Option<String>,
}

impl KwpAuditLogRecord {
    fn body_for_hash(&self) -> KwpAuditLogBody {
        KwpAuditLogBody {
            ts_ms: self.ts_ms,
            run_id: self.run_id.clone(),
            invocation_id: self.invocation_id.clone(),
            module_id: self.module_id.clone(),
            digest: self.digest.clone(),
            event: self.event.clone(),
            decision: self.decision,
            detail: self.detail.clone(),
            prev: self.prev.clone(),
        }
    }
}

impl KwpAuditLogBody {
    fn into_record(self, hash: String) -> KwpAuditLogRecord {
        KwpAuditLogRecord {
            ts_ms: self.ts_ms,
            run_id: self.run_id,
            invocation_id: self.invocation_id,
            module_id: self.module_id,
            digest: self.digest,
            event: self.event,
            decision: self.decision,
            detail: self.detail,
            prev: self.prev,
            hash,
        }
    }
}

pub fn kwp_audit_log_path(target: impl AsRef<Path>, run_id: &str) -> PathBuf {
    crate::run_artifacts::run_artifact_path(target, run_id, "kwp-audit.jsonl")
}

pub fn kwp_bus_log_path(target: impl AsRef<Path>, run_id: &str) -> PathBuf {
    crate::run_artifacts::run_artifact_path(target, run_id, "kwp-bus.jsonl")
}

pub fn read_kwp_audit_log(
    target: impl AsRef<Path>,
    run_id: &str,
) -> Result<Vec<KwpAuditLogRecord>, KwpError> {
    let path = kwp_audit_log_path(target, run_id);
    read_kwp_audit_log_path(&path)
}

pub fn read_kwp_bus_log(
    target: impl AsRef<Path>,
    run_id: &str,
) -> Result<Vec<KwpBusEvent>, KwpError> {
    let path = kwp_bus_log_path(target, run_id);
    let text = fs::read_to_string(&path)
        .map_err(|error| KwpError::Internal(format!("could not read KWP bus log {}: {error}", path.display())))?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line).map_err(|error| {
                KwpError::Internal(format!("could not parse KWP bus log {}: {error}", path.display()))
            })
        })
        .collect()
}

pub fn kwp_audit_log_integrity(
    records: &[KwpAuditLogRecord],
) -> Result<KwpAuditIntegrity, KwpError> {
    let mut errors = Vec::new();
    let mut previous_hash: Option<&str> = None;
    for (index, record) in records.iter().enumerate() {
        verify_kwp_audit_prev(index, record, previous_hash, &mut errors);
        let expected_hash = kwp_audit_record_hash(&record.body_for_hash())?;
        if record.hash != expected_hash {
            errors.push(kwp_audit_integrity_error(
                index,
                "hash",
                Some(expected_hash),
                Some(record.hash.clone()),
                "audit record hash does not match record body",
            ));
        }
        previous_hash = Some(record.hash.as_str());
    }
    Ok(KwpAuditIntegrity {
        ok: errors.is_empty(),
        errors,
    })
}

pub fn read_kwp_audit_log_path(path: &Path) -> Result<Vec<KwpAuditLogRecord>, KwpError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let body = fs::read_to_string(path)
        .map_err(|error| KwpError::Internal(format!("could not read KWP audit log {}: {error}", path.display())))?;
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line).map_err(|error| {
                KwpError::Internal(format!("could not parse KWP audit log {}: {error}", path.display()))
            })
        })
        .collect()
}

fn verify_kwp_audit_prev(
    index: usize,
    record: &KwpAuditLogRecord,
    previous_hash: Option<&str>,
    errors: &mut Vec<KwpAuditIntegrityError>,
) {
    match (index, previous_hash, record.prev.as_deref()) {
        (0, _, None) => {}
        (0, _, Some(actual)) => errors.push(kwp_audit_integrity_error(
            index,
            "prev",
            None,
            Some(actual.to_string()),
            "first audit record must not reference a previous hash",
        )),
        (_, Some(expected), Some(actual)) if expected == actual => {}
        (_, Some(expected), actual) => errors.push(kwp_audit_integrity_error(
            index,
            "prev",
            Some(expected.to_string()),
            actual.map(str::to_string),
            "audit record does not link to the previous record hash",
        )),
        (_, None, actual) => errors.push(kwp_audit_integrity_error(
            index,
            "prev",
            None,
            actual.map(str::to_string),
            "audit record has no previous record to link from",
        )),
    }
}

fn kwp_audit_integrity_error(
    index: usize,
    field: &str,
    expected: Option<String>,
    actual: Option<String>,
    message: &str,
) -> KwpAuditIntegrityError {
    KwpAuditIntegrityError {
        index,
        field: field.to_string(),
        expected,
        actual,
        message: message.to_string(),
    }
}

fn append_kwp_audit_log_record(path: &Path, body: KwpAuditLogBody) -> Result<KwpAuditLogRecord, KwpError> {
    let hash = kwp_audit_record_hash(&body)?;
    let record = body.into_record(hash);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| KwpError::Internal(format!("could not create KWP audit dir {}: {error}", parent.display())))?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| KwpError::Internal(format!("could not open KWP audit log {}: {error}", path.display())))?;
    let line = serde_json::to_string(&record)
        .map_err(|error| KwpError::Internal(format!("could not serialize KWP audit record: {error}")))?;
    writeln!(file, "{line}")
        .map_err(|error| KwpError::Internal(format!("could not append KWP audit log {}: {error}", path.display())))?;
    Ok(record)
}

fn append_kwp_bus_event(path: &Path, event: KwpBusEvent) -> Result<(), KwpError> {
    ensure_jsonl_append_target(path, "bus.log")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| KwpError::Internal(format!("could not create KWP bus dir {}: {error}", parent.display())))?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| KwpError::Internal(format!("could not open KWP bus log {}: {error}", path.display())))?;
    let line = serde_json::to_string(&event)
        .map_err(|error| KwpError::Internal(format!("could not serialize KWP bus event: {error}")))?;
    writeln!(file, "{line}")
        .map_err(|error| KwpError::Internal(format!("could not append KWP bus log {}: {error}", path.display())))
}

fn ensure_jsonl_append_target(path: &Path, label: &str) -> Result<(), KwpError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(KwpError::denied(format!("{label}.symlink")))
        }
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(KwpError::Internal(format!(
            "{label} target is not a file: {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(KwpError::Internal(format!("could not inspect {}: {error}", path.display()))),
    }
}

fn kwp_audit_record_hash(body: &KwpAuditLogBody) -> Result<String, KwpError> {
    let bytes = serde_json::to_vec(body)
        .map_err(|error| KwpError::Internal(format!("could not hash KWP audit record: {error}")))?;
    Ok(sha256_digest(&bytes).0)
}

fn last_kwp_audit_hash(path: &Path) -> Result<Option<String>, KwpError> {
    let records = read_kwp_audit_log_path(path)?;
    Ok(records.last().map(|record| record.hash.clone()))
}

pub struct CapabilityBroker {
    pub fs: Arc<dyn FsBackend>,
    pub net: Arc<dyn NetBackend>,
    pub runtime: Arc<dyn RuntimeBackend>,
    pub bus: Arc<dyn BusBackend>,
    pub findings: Arc<dyn FindingBackend>,
    pub artifacts: Arc<dyn ArtifactBackend>,
    pub mcp: Arc<dyn McpBackend>,
    pub fuzz: Arc<dyn FuzzBackend>,
    pub mcp_catalog: Arc<McpCatalog>,
    pub audit: Arc<dyn AuditSink>,
}

impl CapabilityBroker {
    pub async fn fs_read(&self, inv: &InvocationAuthority, scope: FsScope, path: &str) -> Result<FsReadResult, KwpError> {
        self.ensure_live(inv, "fs.read").await?;
        let Some(grant) = inv.grant().fs_scope(scope) else {
            return self.deny(inv, "fs.read", KwpError::denied("fs")).await;
        };
        if validate_relative_path(path).is_err() {
            return self.deny(inv, "fs.read", KwpError::denied("fs.path")).await;
        }
        let result = self.fs.read(scope, path, 0, None).await;
        if let Ok(read) = &result {
            if let Err(error) = inv
                .reserve_fs_access(grant, path, read.data.len() as u64)
                .await
            {
                return self.deny(inv, "fs.read", error).await;
            }
        }
        self.record(inv, "fs.read", &result).await;
        result
    }

    pub async fn fs_write(&self, inv: &InvocationAuthority, scope: FsScope, path: &str, data: Vec<u8>) -> Result<u64, KwpError> {
        self.ensure_live(inv, "fs.write").await?;
        let Some(grant) = inv
            .grant()
            .fs_scope(scope)
            .filter(|grant| grant.mode == FsMode::Rw)
        else {
            return self.deny(inv, "fs.write", KwpError::denied("fs.write")).await;
        };
        if validate_relative_path(path).is_err() {
            return self.deny(inv, "fs.write", KwpError::denied("fs.path")).await;
        }
        if let Err(error) = inv.reserve_fs_access(grant, path, data.len() as u64).await {
            return self.deny(inv, "fs.write", error).await;
        }
        let result = self.fs.write(scope, path, data, false).await;
        self.record(inv, "fs.write", &result).await;
        result
    }

    pub async fn net_fetch(&self, inv: &InvocationAuthority, request: NetFetchRequest) -> Result<NetFetchResult, KwpError> {
        self.ensure_live(inv, "net.fetch").await?;
        let Some(grant) = inv.grant().net.as_ref() else {
            return self.deny(inv, "net.fetch", KwpError::denied("net")).await;
        };
        let request = match validate_net_fetch_request(grant, request) {
            Ok(validated) => validated.request,
            Err(error) => return self.deny(inv, "net.fetch", error).await,
        };
        if let Err(error) = inv.reserve_net_request(grant, &request).await {
            return self.deny(inv, "net.fetch", error).await;
        }
        let result = self.net.fetch(request).await;
        if let Ok(result) = &result {
            if let Err(error) = inv.reserve_net_response(grant, result).await {
                return self.deny(inv, "net.fetch", error).await;
            }
        }
        self.record(inv, "net.fetch", &result).await;
        result
    }

    pub async fn runtime_query(&self, inv: &InvocationAuthority, request: RuntimeQueryRequest) -> Result<RuntimeQueryResult, KwpError> {
        self.ensure_live(inv, "runtime.query").await?;
        let Some(grant) = inv.grant().runtime.as_ref() else {
            return self.deny(inv, "runtime.query", KwpError::denied("runtime")).await;
        };
        if inv.computed_cost_usd().await >= grant.max_cost_usd_per_invocation {
            return self.deny(inv, "runtime.query", KwpError::RuntimeBudget).await;
        }
        let result = self.runtime.query(with_provenance(inv, request)).await;
        if let Ok(result) = &result {
            inv.add_runtime_cost(result.cost_usd).await;
        }
        self.record(inv, "runtime.query", &result).await;
        result
    }

    pub async fn bus_publish(&self, inv: &InvocationAuthority, topic: String, payload: Value) -> Result<(), KwpError> {
        self.ensure_live(inv, "bus.publish").await?;
        if !inv.grant().bus.produce.iter().any(|pattern| pattern.matches(&topic)) {
            return self.deny(inv, "bus.publish", KwpError::denied("bus.produce")).await;
        }
        let result = self.bus.publish(origin(inv), topic, payload).await;
        self.record(inv, "bus.publish", &result).await;
        result
    }

    pub async fn findings_create(&self, inv: &InvocationAuthority, findings: Vec<Value>) -> Result<FindingsCreateResult, KwpError> {
        self.ensure_live(inv, "findings.create").await?;
        let Some(grant) = inv.grant().findings.as_ref().filter(|grant| grant.create) else {
            return self.deny(inv, "findings.create", KwpError::denied("findings.create")).await;
        };
        if let Some(max) = grant.max_per_invocation {
            if findings.len() > max as usize {
                return self.deny(inv, "findings.create", KwpError::quota("findings.count")).await;
            }
        }
        let result = self.findings.create(origin(inv), findings).await;
        self.record(inv, "findings.create", &result).await;
        result
    }

    pub async fn artifacts_record(&self, inv: &InvocationAuthority, artifacts: Vec<ArtifactRef>) -> Result<Vec<ArtifactRef>, KwpError> {
        self.ensure_live(inv, "artifacts.record").await?;
        if inv.grant().artifacts.as_ref().filter(|grant| grant.write).is_none() {
            return self.deny(inv, "artifacts.record", KwpError::denied("artifacts.write")).await;
        }
        if let Err(error) = validate_artifact_refs(&artifacts) {
            return self.deny(inv, "artifacts.record", error).await;
        }
        let result = self.artifacts.record(origin(inv), artifacts).await;
        self.record(inv, "artifacts.record", &result).await;
        result
    }

    pub async fn mcp_call(&self, inv: &InvocationAuthority, request: McpCallRequest) -> Result<McpCallResult, KwpError> {
        self.ensure_live(inv, "mcp.call").await?;
        if let Err(error) = inv.ensure_invocation_id(&request.invocation_id) {
            return self.deny(inv, "mcp.call", error).await;
        }
        let Some(grant) = inv.grant().mcp_grant(&request.alias) else {
            return self.deny(inv, "mcp.call", KwpError::denied("mcp")).await;
        };
        if !grant.allows_tool(&request.tool) {
            return self.deny(inv, "mcp.call", KwpError::denied("mcp.tool")).await;
        }
        if let Err(error) = inv.reserve_mcp_call(grant, &request.limits).await {
            return self.deny(inv, "mcp.call", error).await;
        }
        let Some(entry) = self.mcp_catalog.get(&request.alias) else {
            return self.deny(inv, "mcp.call", KwpError::denied("mcp.mount")).await;
        };
        if !entry.tools.contains_key(&request.tool) {
            return self.deny(inv, "mcp.call", KwpError::denied("mcp.catalog.tool")).await;
        }
        let result = self
            .mcp
            .call(mcp_session(inv, &request.alias), request)
            .await
            .and_then(|result| validate_mcp_result(result));
        self.record(inv, "mcp.call", &result).await;
        result
    }

    pub async fn fuzz_run(&self, inv: &InvocationAuthority, request: FuzzRunRequest) -> Result<FuzzRunResult, KwpError> {
        self.ensure_live(inv, "fuzz.run").await?;
        if let Err(error) = inv.ensure_invocation_id(&request.invocation_id) {
            return self.deny(inv, "fuzz.run", error).await;
        }
        let Some(grant) = inv.grant().fuzz.as_ref() else {
            return self.deny(inv, "fuzz.run", KwpError::denied("fuzz")).await;
        };
        if !grant.allows_engine(request.engine) {
            return self.deny(inv, "fuzz.run", KwpError::denied("fuzz.engine")).await;
        }
        if request.sandbox.network && !grant.network {
            return self.deny(inv, "fuzz.run", KwpError::denied("fuzz.network")).await;
        }
        if inv
            .grant()
            .artifacts
            .as_ref()
            .filter(|grant| grant.write)
            .is_none()
        {
            return self.deny(inv, "fuzz.run", KwpError::denied("artifacts.write")).await;
        }
        if let Err(error) = validate_fuzz_request_paths(&request) {
            return self.deny(inv, "fuzz.run", error).await;
        }
        if let Err(error) = inv.reserve_fuzz_job(grant, &request).await {
            return self.deny(inv, "fuzz.run", error).await;
        }
        let result = self.fuzz.run(origin(inv), request).await.and_then(validate_fuzz_result);
        self.record(inv, "fuzz.run", &result).await;
        result
    }

    async fn ensure_live(&self, inv: &InvocationAuthority, event: &str) -> Result<(), KwpError> {
        let result = inv.ensure_active().and_then(|_| inv.ensure_epoch_current());
        if result.is_err() {
            self.record(inv, event, &result).await;
        }
        result
    }

    async fn deny<T>(&self, inv: &InvocationAuthority, event: &str, error: KwpError) -> Result<T, KwpError> {
        let result = Err(error);
        self.record(inv, event, &result).await;
        result
    }

    async fn record<T>(&self, inv: &InvocationAuthority, event: &str, result: &Result<T, KwpError>) {
        let (decision, detail) = match result {
            Ok(_) => (AuditDecision::Allow, Value::Null),
            Err(error) => (
                AuditDecision::Deny,
                serde_json::json!({ "errorCode": error.code(), "error": error.to_string() }),
            ),
        };
        self.audit
            .record(AuditRecord {
                event: event.to_string(),
                decision,
                module_id: inv.module_id().clone(),
                digest: inv.digest().clone(),
                invocation_id: inv.invocation_id().clone(),
                detail,
            })
            .await;
    }
}

fn origin(inv: &InvocationAuthority) -> EventOrigin {
    EventOrigin {
        module_id: inv.module_id().clone(),
        digest: inv.digest().clone(),
        invocation_id: inv.invocation_id().clone(),
    }
}

fn mcp_session(inv: &InvocationAuthority, alias: &str) -> McpSessionKey {
    McpSessionKey {
        alias: alias.to_string(),
        module_id: inv.module_id().clone(),
        module_digest: inv.digest().clone(),
        run_id: inv.run_id().clone(),
        invocation_id: inv.invocation_id().clone(),
    }
}

fn validate_mcp_result(result: McpCallResult) -> Result<McpCallResult, KwpError> {
    validate_artifact_refs(&result.artifacts)?;
    Ok(result)
}

fn validate_fuzz_result(result: FuzzRunResult) -> Result<FuzzRunResult, KwpError> {
    validate_artifact_refs(&result.artifacts)?;
    Ok(result)
}

fn with_provenance(inv: &InvocationAuthority, mut request: RuntimeQueryRequest) -> RuntimeQueryRequest {
    let preamble = format!(
        "Kuzushi provenance: module={} digest={} invocation={}",
        inv.module_id().0,
        inv.digest().0,
        inv.invocation_id().0
    );
    request.system_prompt = Some(match request.system_prompt {
        Some(existing) => format!("{preamble}\n\n{existing}"),
        None => preamble,
    });
    request
}

#[derive(Debug)]
struct ValidatedNetFetch {
    request: NetFetchRequest,
    response_byte_limit: Option<u64>,
}

struct NetResponseArtifactRequest {
    path: String,
    media_type: Option<String>,
}

impl NetResponseArtifactRequest {
    fn from_request(request: &NetFetchRequest) -> Option<Self> {
        request.response_artifact_path.as_ref().map(|path| Self {
            path: path.clone(),
            media_type: request.response_media_type.clone(),
        })
    }
}

fn validate_net_fetch_request(grant: &NetGrant, request: NetFetchRequest) -> Result<ValidatedNetFetch, KwpError> {
    let endpoint = parse_https_endpoint(&request.url)?;
    if is_forbidden_net_host(&endpoint.host) {
        return Err(KwpError::denied("net.ssr.host"));
    }
    if !grant.allow.iter().any(|pattern| pattern.matches(&endpoint.host, endpoint.port)) {
        return Err(KwpError::denied("net.host"));
    }
    if let Some(credential_name) = request.credential_name.as_deref() {
        validate_named_credential(grant, credential_name)?;
    }
    validate_net_request_size(grant, &request)?;
    ensure_endpoint_resolves_publicly(&endpoint)?;
    Ok(ValidatedNetFetch {
        request: with_host_controlled_headers(strip_untrusted_headers(request))?,
        response_byte_limit: grant.max_bytes_per_invocation,
    })
}

struct NetEndpoint {
    host: String,
    port: u16,
}

fn parse_https_endpoint(raw: &str) -> Result<NetEndpoint, KwpError> {
    let url = Url::parse(raw).map_err(|_| KwpError::denied("net.url"))?;
    if url.scheme() != "https" {
        return Err(KwpError::denied("net.scheme"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(KwpError::denied("net.userinfo"));
    }
    let host = url
        .host_str()
        .map(normalized_net_host)
        .filter(|host| !host.is_empty())
        .ok_or_else(|| KwpError::denied("net.host"))?;
    let port = url.port_or_known_default().ok_or_else(|| KwpError::denied("net.port"))?;
    Ok(NetEndpoint { host, port })
}

fn normalized_net_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn validate_named_credential(grant: &NetGrant, credential_name: &str) -> Result<(), KwpError> {
    if grant.credentials.iter().any(|allowed| allowed == credential_name) {
        Ok(())
    } else {
        Err(KwpError::denied("net.credential"))
    }
}

fn validate_net_request_size(grant: &NetGrant, request: &NetFetchRequest) -> Result<(), KwpError> {
    let Some(max) = grant.max_bytes_per_invocation else {
        return Ok(());
    };
    check_u64(Some(net_request_body_len(request)?), Some(max), "net.bytes")
}

fn net_request_body_len(request: &NetFetchRequest) -> Result<u64, KwpError> {
    let Some(body) = request.body_base64.as_ref() else {
        return Ok(0);
    };
    Ok(BASE64
        .decode(body.as_bytes())
        .map_err(|_| KwpError::BadRequest("net body_base64 is invalid".to_string()))?
        .len() as u64)
}

fn net_result_body_len(result: &NetFetchResult) -> Result<u64, KwpError> {
    let Some(body) = result.body_base64.as_ref() else {
        return Ok(0);
    };
    Ok(BASE64
        .decode(body.as_bytes())
        .map_err(|_| KwpError::Internal("net response body_base64 is invalid".to_string()))?
        .len() as u64)
}

fn ensure_endpoint_resolves_publicly(endpoint: &NetEndpoint) -> Result<(), KwpError> {
    if let Ok(ip) = endpoint.host.parse::<IpAddr>() {
        return ensure_public_ip(ip);
    }
    let addrs = (endpoint.host.as_str(), endpoint.port)
        .to_socket_addrs()
        .map_err(|_| KwpError::denied("net.dns"))?
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        return Err(KwpError::denied("net.dns"));
    }
    for addr in addrs {
        ensure_public_socket(addr)?;
    }
    Ok(())
}

fn ensure_public_socket(addr: SocketAddr) -> Result<(), KwpError> {
    ensure_public_ip(addr.ip())
}

fn ensure_public_ip(ip: IpAddr) -> Result<(), KwpError> {
    if is_forbidden_net_ip(ip) {
        Err(KwpError::denied("net.ssr.ip"))
    } else {
        Ok(())
    }
}

fn is_forbidden_net_host(host: &str) -> bool {
    matches!(
        host,
        "localhost" | "metadata" | "metadata.google.internal" | "169.254.169.254"
    ) || host.ends_with(".localhost")
        || host.ends_with(".local")
}

fn is_forbidden_net_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_forbidden_ipv4(ip),
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
        }
    }
}

fn is_forbidden_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_multicast()
        || octets[0] == 0
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 169 && octets[1] == 254)
        || (octets[0] == 198 && matches!(octets[1], 18 | 19))
        || octets[0] >= 240
}

fn strip_untrusted_headers(mut request: NetFetchRequest) -> NetFetchRequest {
    request.headers.retain(|name, _| {
        let lower = name.to_ascii_lowercase();
        lower != "authorization" && lower != "cookie" && !lower.starts_with("proxy-") && !lower.starts_with("x-forwarded-")
    });
    request
}

fn with_host_controlled_headers(mut request: NetFetchRequest) -> Result<NetFetchRequest, KwpError> {
    if let Some(credential_name) = request.credential_name.as_deref() {
        if let Some(token) = named_credential_token(credential_name)? {
            request
                .headers
                .insert("authorization".to_string(), format!("Bearer {token}"));
        }
    }
    Ok(request)
}

fn spill_net_response_artifact(
    root: &Path,
    grant: &ArtifactsGrant,
    request: NetResponseArtifactRequest,
    headers: &BTreeMap<String, String>,
    body: &[u8],
) -> Result<ArtifactRef, KwpError> {
    validate_relative_path(&request.path).map_err(|_| KwpError::denied("artifact.path"))?;
    check_u64(
        Some(body.len() as u64),
        grant.max_bytes_per_invocation,
        "artifacts.bytes",
    )?;
    let media_type = request
        .media_type
        .filter(|value| !value.trim().is_empty())
        .or_else(|| response_content_type(headers))
        .unwrap_or_else(|| "application/octet-stream".to_string());
    let path = resolve_write_path(root, &request.path)?;
    fs::write(&path, body).map_err(|error| KwpError::Internal(error.to_string()))?;
    let artifact = ArtifactRef {
        path: request.path,
        media_type,
        sha256: None,
    };
    let mut total_bytes = 0;
    verify_artifact_ref(root, grant, &mut total_bytes, artifact)
}

fn response_content_type(headers: &BTreeMap<String, String>) -> Option<String> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.to_string())
        .filter(|value| !value.trim().is_empty())
}

fn named_credential_token(name: &str) -> Result<Option<String>, KwpError> {
    let env_name = credential_env_name(name)?;
    Ok(std::env::var(env_name).ok().filter(|value| !value.trim().is_empty()))
}

fn credential_env_name(name: &str) -> Result<String, KwpError> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(KwpError::denied("net.credential"));
    }
    Ok(format!("KUZUSHI_CREDENTIAL_{}", name.to_ascii_uppercase()))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum RpcId {
    Number(u64),
    String(String),
}

impl From<u64> for RpcId {
    fn from(value: u64) -> Self {
        Self::Number(value)
    }
}

impl From<String> for RpcId {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<&str> for RpcId {
    fn from(value: &str) -> Self {
        Self::String(value.to_string())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum RpcMessage {
    Request {
        jsonrpc: String,
        id: RpcId,
        method: String,
        #[serde(default)]
        params: Value,
    },
    Response {
        jsonrpc: String,
        id: RpcId,
        result: Value,
    },
    ErrorResponse {
        jsonrpc: String,
        id: RpcId,
        error: RpcError,
    },
    Notification {
        jsonrpc: String,
        method: String,
        #[serde(default)]
        params: Value,
    },
}

impl RpcMessage {
    pub fn request(id: impl Into<RpcId>, method: impl Into<String>, params: Value) -> Self {
        Self::Request {
            jsonrpc: "2.0".to_string(),
            id: id.into(),
            method: method.into(),
            params,
        }
    }

    pub fn response(id: impl Into<RpcId>, result: Value) -> Self {
        Self::Response {
            jsonrpc: "2.0".to_string(),
            id: id.into(),
            result,
        }
    }

    pub fn error_response(id: impl Into<RpcId>, error: RpcError) -> Self {
        Self::ErrorResponse {
            jsonrpc: "2.0".to_string(),
            id: id.into(),
            error,
        }
    }

    pub fn notification(method: impl Into<String>, params: Value) -> Self {
        Self::Notification {
            jsonrpc: "2.0".to_string(),
            method: method.into(),
            params,
        }
    }

    fn jsonrpc_version(&self) -> &str {
        match self {
            Self::Request { jsonrpc, .. }
            | Self::Response { jsonrpc, .. }
            | Self::ErrorResponse { jsonrpc, .. }
            | Self::Notification { jsonrpc, .. } => jsonrpc,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

impl From<KwpError> for RpcError {
    fn from(error: KwpError) -> Self {
        Self { code: error.code(), message: error.to_string() }
    }
}

pub fn encode_rpc_line(message: &RpcMessage) -> Result<Vec<u8>, KwpError> {
    validate_rpc_version(message)?;
    let mut bytes = serde_json::to_vec(message).map_err(|error| KwpError::Internal(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn decode_rpc_line(bytes: &[u8]) -> Result<RpcMessage, KwpError> {
    let message = serde_json::from_slice(bytes).map_err(|error| KwpError::BadRequest(error.to_string()))?;
    validate_rpc_version(&message)?;
    Ok(message)
}

fn validate_rpc_version(message: &RpcMessage) -> Result<(), KwpError> {
    if message.jsonrpc_version() == "2.0" {
        Ok(())
    } else {
        Err(KwpError::BadRequest("jsonrpc version must be 2.0".to_string()))
    }
}

#[async_trait]
pub trait WorkerTransport: Send + Sync {
    async fn send(&self, message: RpcMessage) -> Result<(), KwpError>;
    async fn recv(&self) -> Result<Option<RpcMessage>, KwpError>;
}

#[async_trait]
pub trait WorkerExecutor: Send + Sync {
    async fn spawn(&self, module: VerifiedModule, mode: WorkerMode) -> Result<SpawnedWorker, KwpError>;
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WorkerMode {
    Serve,
    Probe,
}

pub struct SpawnedWorker {
    pub pid: u32,
    pub transport: Arc<dyn WorkerTransport>,
    pub kill: Arc<dyn Fn() + Send + Sync>,
}

pub struct NodeWorkerRun<'a> {
    pub command: Command,
    pub module: &'a VerifiedModule,
    pub tool_name: &'a str,
    pub input: &'a Value,
    pub context: &'a crate::modules::ToolExecutionContext<'a>,
    pub runtime: Option<&'a dyn crate::runtime::AgentRuntime>,
}

pub fn run_node_worker_tool_blocking(mut run: NodeWorkerRun<'_>) -> Result<Value, KwpError> {
    let invocation_id = InvocationId(format!("kwp-{}", uuid::Uuid::new_v4()));
    let run_id = RunId(
        run.context
            .run_id()
            .unwrap_or_else(|| format!("run-{}", uuid::Uuid::new_v4())),
    );
    let mut child = spawn_node_worker(&mut run.command, run.module)?;
    let mut stdin = take_worker_stdin(&mut child)?;
    let stdout = take_worker_stdout(&mut child)?;
    tag_worker_stderr(&mut child, run.module, run.tool_name);

    let mut session = WorkerHostSession {
        module: run.module,
        tool_name: run.tool_name,
        invocation_id,
        run_id,
        context: run.context,
        runtime: run.runtime,
        runtime_cost_usd: 0.0,
        fs_access: FsAccessMeter::default(),
        net_access: NetAccessMeter::default(),
        mcp_calls: BTreeMap::new(),
        mcp_host: HostMcpBroker::from_config(run.context.config, run.context.workspace),
        fuzz_jobs: 0,
        fuzz_host: HostFuzzExecutor::from_config(run.context.config, run.context.workspace),
        deadline: worker_deadline(run.context.config),
        epoch: KWP_WORKER_EPOCH,
        cancel_recorded: false,
        settled: false,
    };
    let receiver = spawn_worker_stdout_reader(stdout);
    let result = session
        .record_invocation_start()
        .and_then(|_| initialize_then_call_worker(&receiver, &mut stdin, run, &mut session));
    let cancel_result = if matches!(&result, Err(KwpError::Deadline)) {
        session.record_invocation_cancel("deadline")
    } else {
        Ok(())
    };
    session.settled = true;
    let audit_result = cancel_result.and_then(|_| session.record_invocation_end(&result));
    let _ = child.kill();
    let _ = child.wait();
    audit_result?;
    result
}

fn spawn_node_worker(command: &mut Command, module: &VerifiedModule) -> Result<Child, KwpError> {
    command
        .current_dir(&module.module_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| KwpError::Internal(format!("could not start KWP worker: {error}")))
}

fn take_worker_stdin(child: &mut Child) -> Result<std::process::ChildStdin, KwpError> {
    child
        .stdin
        .take()
        .ok_or_else(|| KwpError::Internal("KWP worker stdin unavailable".to_string()))
}

fn take_worker_stdout(child: &mut Child) -> Result<std::process::ChildStdout, KwpError> {
    child
        .stdout
        .take()
        .ok_or_else(|| KwpError::Internal("KWP worker stdout unavailable".to_string()))
}

fn tag_worker_stderr(child: &mut Child, module: &VerifiedModule, tool_name: &str) {
    let Some(stderr) = child.stderr.take() else {
        return;
    };
    let module_id = module.module_id.0.clone();
    let digest = module.digest.0.clone();
    let tool = tool_name.to_string();
    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            eprintln!("[kwp:{module_id}:{digest}:{tool}:stderr] {line}");
        }
    });
}

fn initialize_then_call_worker(
    receiver: &mpsc::Receiver<Result<Option<RpcMessage>, KwpError>>,
    stdin: &mut impl Write,
    run: NodeWorkerRun<'_>,
    session: &mut WorkerHostSession<'_>,
) -> Result<Value, KwpError> {
    let initialize_id = RpcId::from(1_u64);
    write_rpc_message(
        stdin,
        &RpcMessage::request(
            initialize_id.clone(),
            "initialize",
            worker_initialize_params(session.module),
        ),
    )?;
    let initialize = drive_worker_until_response(receiver, stdin, &initialize_id, session, false)?;
    validate_worker_initialize(&initialize, session.module, session.tool_name)?;

    let tool_call_id = RpcId::from(2_u64);
    write_rpc_message(
        stdin,
        &RpcMessage::request(
            tool_call_id.clone(),
            "tools/call",
            worker_tool_call_params(
                session.module,
                session.tool_name,
                run.input,
                run.context,
                &session.invocation_id,
                &session.run_id,
            ),
        ),
    )?;
    drive_worker_until_response(receiver, stdin, &tool_call_id, session, true)
}

fn worker_initialize_params(module: &VerifiedModule) -> Value {
    serde_json::json!({
        "_kuzushi": {
            "protocolVersion": KWP_VERSION,
            "moduleDigest": module.digest.0,
            "descriptorHash": module.descriptor_hash,
            "grant": module.grant.as_ref(),
            "limits": {
                "maxConcurrentInvocations": 1
            }
        }
    })
}

fn worker_tool_call_params(
    module: &VerifiedModule,
    tool_name: &str,
    input: &Value,
    ctx: &crate::modules::ToolExecutionContext<'_>,
    invocation_id: &InvocationId,
    run_id: &RunId,
) -> Value {
    serde_json::json!({
        "name": tool_name,
        "arguments": input,
        "_kuzushi": {
            "invocationId": invocation_id.0,
            "runId": run_id.0,
            "epoch": KWP_WORKER_EPOCH,
        },
        "context": worker_context_json(module, ctx, invocation_id, run_id),
    })
}

fn worker_context_json(
    module: &VerifiedModule,
    ctx: &crate::modules::ToolExecutionContext<'_>,
    invocation_id: &InvocationId,
    run_id: &RunId,
) -> Value {
    serde_json::json!({
        "cwd": worker_context_cwd(module, ctx),
        "config": ctx.config,
        "kwp": {
            "version": KWP_VERSION,
            "invocationId": invocation_id.0,
            "runId": run_id.0,
            "epoch": KWP_WORKER_EPOCH,
            "moduleDigest": module.digest.0,
            "descriptorHash": module.descriptor_hash,
        }
    })
}

fn worker_context_cwd(module: &VerifiedModule, ctx: &crate::modules::ToolExecutionContext<'_>) -> String {
    ctx.workspace
        .map(|workspace| workspace.root().display().to_string())
        .unwrap_or_else(|| module.module_root.display().to_string())
}

fn write_rpc_message(writer: &mut impl Write, message: &RpcMessage) -> Result<(), KwpError> {
    let bytes = encode_rpc_line(message)?;
    writer
        .write_all(&bytes)
        .map_err(|error| KwpError::Internal(format!("could not write KWP message: {error}")))?;
    writer
        .flush()
        .map_err(|error| KwpError::Internal(format!("could not flush KWP message: {error}")))
}

fn drive_worker_until_response(
    receiver: &mpsc::Receiver<Result<Option<RpcMessage>, KwpError>>,
    stdin: &mut impl Write,
    request_id: &RpcId,
    session: &mut WorkerHostSession<'_>,
    attach_metrics: bool,
) -> Result<Value, KwpError> {
    loop {
        let message = match read_next_worker_message(receiver, session.deadline, session.tool_name) {
            Ok(message) => message,
            Err(KwpError::Deadline) if attach_metrics => {
                cancel_worker_invocation(stdin, receiver, request_id, session, "deadline");
                return Err(KwpError::Deadline);
            }
            Err(error) => return Err(error),
        };
        match message {
            RpcMessage::Response { id, result, .. } if &id == request_id => {
                if let Err(KwpError::Deadline) = session.ensure_before_deadline() {
                    if attach_metrics {
                        cancel_worker_invocation(stdin, receiver, request_id, session, "deadline");
                    }
                    return Err(KwpError::Deadline);
                }
                return Ok(if attach_metrics {
                    session.attach_host_metrics(result)
                } else {
                    result
                });
            }
            RpcMessage::ErrorResponse { id, error, .. } if &id == request_id => {
                if let Err(KwpError::Deadline) = session.ensure_before_deadline() {
                    if attach_metrics {
                        cancel_worker_invocation(stdin, receiver, request_id, session, "deadline");
                    }
                    return Err(KwpError::Deadline);
                }
                return Err(KwpError::Internal(format!("worker error {}: {}", error.code, error.message)));
            }
            RpcMessage::Request { id, method, params, .. } => {
                let response = session.handle_worker_request(method, params);
                write_rpc_message(stdin, &response_message(id, response))?;
            }
            RpcMessage::Response { .. } | RpcMessage::ErrorResponse { .. } | RpcMessage::Notification { .. } => {}
        }
    }
}

fn cancel_worker_invocation(
    stdin: &mut impl Write,
    receiver: &mpsc::Receiver<Result<Option<RpcMessage>, KwpError>>,
    request_id: &RpcId,
    session: &mut WorkerHostSession<'_>,
    reason: &str,
) {
    let _ = session.record_invocation_cancel(reason);
    session.settled = true;
    let _ = write_rpc_message(
        stdin,
        &RpcMessage::notification(
            "notifications/cancelled",
            serde_json::json!({
                "invocationId": session.invocation_id.0,
                "reason": reason,
            }),
        ),
    );
    drain_worker_after_settlement(receiver, stdin, request_id, session);
}

fn drain_worker_after_settlement(
    receiver: &mpsc::Receiver<Result<Option<RpcMessage>, KwpError>>,
    stdin: &mut impl Write,
    request_id: &RpcId,
    session: &mut WorkerHostSession<'_>,
) {
    let end = Instant::now()
        .checked_add(KWP_CANCEL_GRACE)
        .unwrap_or_else(|| Instant::now() + KWP_CANCEL_GRACE);
    while let Some(remaining) = end.checked_duration_since(Instant::now()) {
        if remaining.is_zero() {
            return;
        }
        match receiver.recv_timeout(remaining) {
            Ok(Ok(Some(RpcMessage::Request { id, method, params, .. }))) => {
                let response = session.handle_worker_request(method, params);
                let _ = write_rpc_message(stdin, &response_message(id, response));
            }
            Ok(Ok(Some(RpcMessage::Response { id, .. } | RpcMessage::ErrorResponse { id, .. })))
                if &id == request_id =>
            {
                // The invocation is already host-settled. Drop the worker's
                // late result and keep the broker open briefly so any cleanup
                // calls are denied and audited by the host.
            }
            Ok(Ok(Some(RpcMessage::Response { .. } | RpcMessage::ErrorResponse { .. } | RpcMessage::Notification { .. }))) => {}
            Ok(Ok(None)) | Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}

fn validate_worker_initialize(
    initialize: &Value,
    module: &VerifiedModule,
    tool_name: &str,
) -> Result<(), KwpError> {
    let version = initialize
        .get("protocolVersion")
        .and_then(Value::as_str)
        .ok_or_else(|| KwpError::BadRequest("worker initialize omitted protocolVersion".to_string()))?;
    if version != KWP_VERSION {
        return Err(KwpError::BadRequest(format!(
            "worker protocolVersion {version:?} does not match host {KWP_VERSION:?}"
        )));
    }
    let descriptor = worker_initialize_descriptor(initialize)?;
    if descriptor.module.id != module.module_id.0 {
        return Err(KwpError::BadRequest(format!(
            "worker module id {module_id:?} does not match approved module {:?}",
            module.module_id.0,
            module_id = descriptor.module.id
        )));
    }
    if !descriptor.tools.iter().any(|tool| tool.name == tool_name) {
        return Err(KwpError::BadRequest(format!(
            "worker initialize did not advertise tool {tool_name:?}"
        )));
    }
    let descriptor_value =
        serde_json::to_value(&descriptor).map_err(|error| KwpError::Internal(error.to_string()))?;
    let descriptor_hash = descriptor_hash_from_value(&descriptor_value)
        .map_err(|error| KwpError::Internal(error.to_string()))?;
    if descriptor_hash != module.descriptor_hash {
        return Err(KwpError::BadRequest(format!(
            "worker descriptor hash changed after approval: lockfile has {}, worker initialized with {}",
            module.descriptor_hash, descriptor_hash
        )));
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct WorkerInitializeDescriptor {
    module: crate::modules::ModuleMetadata,
    tools: Vec<crate::modules::ToolDescriptor>,
}

fn worker_initialize_descriptor(initialize: &Value) -> Result<WorkerInitializeDescriptor, KwpError> {
    serde_json::from_value(serde_json::json!({
        "module": initialize.get("module").cloned().unwrap_or(Value::Null),
        "tools": initialize.get("tools").cloned().unwrap_or(Value::Null),
    }))
    .map_err(|error| KwpError::BadRequest(format!("worker initialize descriptor is invalid: {error}")))
}

fn spawn_worker_stdout_reader(
    stdout: std::process::ChildStdout,
) -> mpsc::Receiver<Result<Option<RpcMessage>, KwpError>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || read_worker_stdout(stdout, sender));
    receiver
}

fn read_worker_stdout(
    stdout: std::process::ChildStdout,
    sender: mpsc::Sender<Result<Option<RpcMessage>, KwpError>>,
) {
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                let _ = sender.send(Ok(None));
                return;
            }
            Ok(_) => {
                if sender.send(decode_rpc_line(line.as_bytes()).map(Some)).is_err() {
                    return;
                }
            }
            Err(error) => {
                let _ = sender.send(Err(KwpError::Internal(format!(
                    "could not read KWP worker output: {error}"
                ))));
                return;
            }
        }
    }
}

fn read_next_worker_message(
    receiver: &mpsc::Receiver<Result<Option<RpcMessage>, KwpError>>,
    deadline: Instant,
    tool_name: &str,
) -> Result<RpcMessage, KwpError> {
    let timeout = remaining_worker_time(deadline)?;
    match receiver.recv_timeout(timeout) {
        Ok(Ok(Some(message))) => Ok(message),
        Ok(Ok(None)) => Err(KwpError::Internal(format!(
            "KWP worker exited before {tool_name} returned a result"
        ))),
        Ok(Err(error)) => Err(error),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(KwpError::Deadline),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(KwpError::Internal(
            "KWP worker stdout reader disconnected".to_string(),
        )),
    }
}

fn remaining_worker_time(deadline: Instant) -> Result<Duration, KwpError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(KwpError::Deadline)
}

fn worker_deadline(config: &crate::config::V2Config) -> Instant {
    let timeout_ms = config
        .runtime
        .worker_watchdog_timeout_ms
        .unwrap_or(crate::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS);
    Instant::now()
        .checked_add(Duration::from_millis(timeout_ms))
        .unwrap_or_else(|| Instant::now() + Duration::from_secs(60 * 60))
}

fn response_message(id: RpcId, result: Result<Value, KwpError>) -> RpcMessage {
    match result {
        Ok(value) => RpcMessage::response(id, value),
        Err(error) => RpcMessage::error_response(id, error.into()),
    }
}

fn ensure_worker_request_authority(
    params: &Value,
    expected_invocation_id: &InvocationId,
    expected_epoch: u64,
) -> Result<(), KwpError> {
    let id = params
        .get("invocationId")
        .or_else(|| params.get("invocation_id"))
        .and_then(Value::as_str)
        .ok_or(KwpError::NoActiveInvocation)?;
    if id != expected_invocation_id.0 {
        return Err(KwpError::NoActiveInvocation);
    }
    let epoch = params
        .get("epoch")
        .or_else(|| params.get("invocationEpoch"))
        .and_then(Value::as_u64)
        .ok_or(KwpError::EpochStale)?;
    if epoch == expected_epoch {
        Ok(())
    } else {
        Err(KwpError::EpochStale)
    }
}

struct WorkerHostSession<'a> {
    module: &'a VerifiedModule,
    tool_name: &'a str,
    invocation_id: InvocationId,
    run_id: RunId,
    context: &'a crate::modules::ToolExecutionContext<'a>,
    runtime: Option<&'a dyn crate::runtime::AgentRuntime>,
    runtime_cost_usd: f64,
    fs_access: FsAccessMeter,
    net_access: NetAccessMeter,
    mcp_calls: BTreeMap<String, u32>,
    mcp_host: HostMcpBroker,
    fuzz_jobs: u32,
    fuzz_host: HostFuzzExecutor,
    deadline: Instant,
    epoch: u64,
    cancel_recorded: bool,
    settled: bool,
}

impl WorkerHostSession<'_> {
    fn handle_worker_request(&mut self, method: String, params: Value) -> Result<Value, KwpError> {
        let event = broker_audit_event(&method);
        let result = self.handle_worker_request_inner(method, params);
        self.record_broker_decision(&event, &result)?;
        result
    }

    fn handle_worker_request_inner(&mut self, method: String, params: Value) -> Result<Value, KwpError> {
        self.ensure_unsettled()?;
        self.ensure_before_deadline()?;
        self.ensure_invocation_param(&params)?;
        match method.as_str() {
            METHOD_FS_READ => self.handle_fs_read(params),
            METHOD_FS_WRITE => self.handle_fs_write(params),
            METHOD_FS_LIST => self.handle_fs_list(params),
            METHOD_FS_STAT => self.handle_fs_stat(params),
            METHOD_FS_REMOVE => self.handle_fs_remove(params),
            METHOD_RUNTIME_QUERY => self.handle_runtime_query(params),
            METHOD_ARTIFACTS_RECORD => self.handle_artifacts_record(params),
            METHOD_FINDINGS_CREATE => self.handle_findings_create(params),
            METHOD_MCP_CALL => self.handle_mcp_call(params),
            METHOD_FUZZ_RUN => self.handle_fuzz_run(params),
            METHOD_NET_FETCH => self.handle_net_fetch(params),
            METHOD_BUS_PUBLISH => self.handle_bus_publish(params),
            _ => Err(KwpError::BadRequest(format!("unknown KWP method {method}"))),
        }
    }

    fn ensure_unsettled(&self) -> Result<(), KwpError> {
        if self.settled {
            Err(KwpError::NoActiveInvocation)
        } else {
            Ok(())
        }
    }

    fn ensure_before_deadline(&self) -> Result<(), KwpError> {
        remaining_worker_time(self.deadline).map(|_| ())
    }

    fn ensure_invocation_param(&self, params: &Value) -> Result<(), KwpError> {
        ensure_worker_request_authority(params, &self.invocation_id, self.epoch)
    }

    fn handle_fs_read(&mut self, params: Value) -> Result<Value, KwpError> {
        let request: WorkerFsReadRequest =
            serde_json::from_value(params).map_err(|error| KwpError::BadRequest(error.to_string()))?;
        let Some(grant) = self.module.grant.fs_scope(request.scope).cloned() else {
            return Err(KwpError::denied("fs"));
        };
        let root = self.scope_root(request.scope)?;
        let path = resolve_read_path(&root, &request.path)?;
        let bytes = fs::read(&path).map_err(|error| KwpError::Internal(error.to_string()))?;
        let offset = request.offset.unwrap_or(0) as usize;
        let length = request.length.map(|value| value as usize);
        let data = slice_bytes(&bytes, offset, length);
        self.reserve_fs_access(&grant, &request.path, data.len() as u64)?;
        Ok(serde_json::json!({
            "dataBase64": BASE64.encode(data),
            "eof": offset.saturating_add(data.len()) >= bytes.len(),
        }))
    }

    fn handle_fs_write(&mut self, params: Value) -> Result<Value, KwpError> {
        let request: WorkerFsWriteRequest =
            serde_json::from_value(params).map_err(|error| KwpError::BadRequest(error.to_string()))?;
        let Some(grant) = self
            .module
            .grant
            .fs_scope(request.scope)
            .filter(|grant| grant.mode == FsMode::Rw)
            .cloned()
        else {
            return Err(KwpError::denied("fs.write"));
        };
        let root = self.scope_root(request.scope)?;
        let path = resolve_write_path(&root, &request.path)?;
        let data = BASE64
            .decode(request.data_base64.as_bytes())
            .map_err(|error| KwpError::BadRequest(error.to_string()))?;
        self.reserve_fs_access(&grant, &request.path, data.len() as u64)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| KwpError::Internal(error.to_string()))?;
        }
        if request.append.unwrap_or(false) {
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|error| KwpError::Internal(error.to_string()))?;
            file.write_all(&data).map_err(|error| KwpError::Internal(error.to_string()))?;
        } else {
            fs::write(&path, &data).map_err(|error| KwpError::Internal(error.to_string()))?;
        }
        Ok(serde_json::json!({ "bytesWritten": data.len() }))
    }

    fn handle_fs_list(&mut self, params: Value) -> Result<Value, KwpError> {
        let request: WorkerFsPathRequest =
            serde_json::from_value(params).map_err(|error| KwpError::BadRequest(error.to_string()))?;
        let Some(grant) = self.module.grant.fs_scope(request.scope).cloned() else {
            return Err(KwpError::denied("fs"));
        };
        self.reserve_fs_access(&grant, &request.path, 0)?;
        let root = self.scope_root(request.scope)?;
        let path = resolve_read_path(&root, &request.path)?;
        let entries = fs::read_dir(&path)
            .map_err(|error| KwpError::Internal(error.to_string()))?
            .map(|entry| fs_list_entry(entry.map_err(|error| KwpError::Internal(error.to_string()))?))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(serde_json::json!({ "entries": entries }))
    }

    fn handle_fs_stat(&mut self, params: Value) -> Result<Value, KwpError> {
        let request: WorkerFsPathRequest =
            serde_json::from_value(params).map_err(|error| KwpError::BadRequest(error.to_string()))?;
        let Some(grant) = self.module.grant.fs_scope(request.scope).cloned() else {
            return Err(KwpError::denied("fs"));
        };
        self.reserve_fs_access(&grant, &request.path, 0)?;
        let root = self.scope_root(request.scope)?;
        let path = resolve_read_path(&root, &request.path)?;
        let metadata = fs::metadata(&path).map_err(|error| KwpError::Internal(error.to_string()))?;
        Ok(fs_metadata_json(&metadata))
    }

    fn handle_fs_remove(&mut self, params: Value) -> Result<Value, KwpError> {
        let request: WorkerFsPathRequest =
            serde_json::from_value(params).map_err(|error| KwpError::BadRequest(error.to_string()))?;
        let Some(grant) = self
            .module
            .grant
            .fs_scope(request.scope)
            .filter(|grant| grant.mode == FsMode::Rw)
            .cloned()
        else {
            return Err(KwpError::denied("fs.remove"));
        };
        self.reserve_fs_access(&grant, &request.path, 0)?;
        let root = self.scope_root(request.scope)?;
        let path = resolve_remove_path(&root, &request.path)?;
        let metadata = fs::metadata(&path).map_err(|error| KwpError::Internal(error.to_string()))?;
        if metadata.is_dir() {
            fs::remove_dir(&path).map_err(|error| KwpError::Internal(error.to_string()))?;
        } else {
            fs::remove_file(&path).map_err(|error| KwpError::Internal(error.to_string()))?;
        }
        Ok(serde_json::json!({ "removed": true }))
    }

    fn reserve_fs_access(
        &mut self,
        grant: &FsScopeGrant,
        path: &str,
        bytes: u64,
    ) -> Result<(), KwpError> {
        reserve_fs_access_in_meter(&mut self.fs_access, grant, path, bytes)
    }

    fn handle_runtime_query(&mut self, params: Value) -> Result<Value, KwpError> {
        let Some(grant) = self.module.grant.runtime.as_ref() else {
            return Err(KwpError::denied("runtime"));
        };
        if self.runtime_cost_usd >= grant.max_cost_usd_per_invocation {
            return Err(KwpError::RuntimeBudget);
        }
        let Some(runtime) = self.runtime else {
            return Err(KwpError::denied("runtime.unavailable"));
        };
        let request_value = params
            .get("request")
            .cloned()
            .ok_or_else(|| KwpError::BadRequest("runtime request omitted".to_string()))?;
        let request: crate::runtime::AgentQueryRequest =
            serde_json::from_value(request_value).map_err(|error| KwpError::BadRequest(error.to_string()))?;
        let response = runtime
            .query_blocking(request)
            .map_err(|error| KwpError::Internal(error.to_string()))?;
        self.runtime_cost_usd += response.cost_usd;
        if self.runtime_cost_usd > grant.max_cost_usd_per_invocation {
            return Err(KwpError::RuntimeBudget);
        }
        serde_json::to_value(response).map_err(|error| KwpError::Internal(error.to_string()))
    }

    fn handle_artifacts_record(&self, params: Value) -> Result<Value, KwpError> {
        let Some(grant) = self.module.grant.artifacts.as_ref().filter(|grant| grant.write) else {
            return Err(KwpError::denied("artifacts.write"));
        };
        let artifacts = artifacts_from_params(&params)?;
        let artifacts = self.verified_artifacts(grant, artifacts)?;
        Ok(serde_json::json!({ "artifacts": artifacts }))
    }

    fn handle_findings_create(&self, params: Value) -> Result<Value, KwpError> {
        let Some(grant) = self.module.grant.findings.as_ref().filter(|grant| grant.create) else {
            return Err(KwpError::denied("findings.create"));
        };
        let Some(store) = self.context.findings_store else {
            return Err(KwpError::denied("findings.unavailable"));
        };
        let findings = params
            .get("findings")
            .cloned()
            .ok_or_else(|| KwpError::BadRequest("findings omitted".to_string()))?;
        let findings = worker_findings_from_value(&findings, self.tool_name)?;
        if grant.max_per_invocation.is_some_and(|max| findings.len() > max as usize) {
            return Err(KwpError::quota("findings.count"));
        }
        ensure_finding_severities_allowed(grant, &findings)?;
        self.record_findings_run(store)?;
        for finding in &findings {
            store
                .insert_finding(&self.run_id.0, finding)
                .map_err(|error| KwpError::Internal(error.to_string()))?;
        }
        Ok(serde_json::json!({ "created": findings.len() }))
    }

    fn handle_mcp_call(&mut self, params: Value) -> Result<Value, KwpError> {
        let request: McpCallRequest =
            serde_json::from_value(params).map_err(|error| KwpError::BadRequest(error.to_string()))?;
        let Some(grant) = self.module.grant.mcp_grant(&request.alias).cloned() else {
            return Err(KwpError::denied("mcp"));
        };
        if !grant.allows_tool(&request.tool) {
            return Err(KwpError::denied("mcp.tool"));
        }
        self.reserve_mcp_call(&grant, &request)?;
        let Some(entry) = self.mcp_host.catalog().get(&request.alias) else {
            return Err(KwpError::denied("mcp.mount"));
        };
        if !entry.tools.contains_key(&request.tool) {
            return Err(KwpError::denied("mcp.catalog.tool"));
        }
        let session = self.mcp_session(&request.alias);
        let result = self.mcp_host.call_blocking(session, request)?;
        let result = self.verified_mcp_result(&grant, result)?;
        serde_json::to_value(result).map_err(|error| KwpError::Internal(error.to_string()))
    }

    fn handle_fuzz_run(&mut self, params: Value) -> Result<Value, KwpError> {
        let request: FuzzRunRequest =
            serde_json::from_value(params).map_err(|error| KwpError::BadRequest(error.to_string()))?;
        if request.invocation_id != self.invocation_id {
            return Err(KwpError::NoActiveInvocation);
        }
        let Some(grant) = self.module.grant.fuzz.clone() else {
            return Err(KwpError::denied("fuzz"));
        };
        if !grant.allows_engine(request.engine) {
            return Err(KwpError::denied("fuzz.engine"));
        }
        if request.sandbox.network && !grant.network {
            return Err(KwpError::denied("fuzz.network"));
        }
        self.ensure_fuzz_artifacts_granted()?;
        validate_fuzz_request_paths(&request)?;
        self.reserve_fuzz_job(&grant, &request)?;
        let result = self.fuzz_host.run_blocking(self.event_origin(), request)?;
        let result = self.verified_fuzz_result(&grant, result)?;
        serde_json::to_value(result).map_err(|error| KwpError::Internal(error.to_string()))
    }

    fn handle_net_fetch(&mut self, params: Value) -> Result<Value, KwpError> {
        let Some(grant) = self.module.grant.net.as_ref() else {
            return Err(KwpError::denied("net"));
        };
        let request: NetFetchRequest =
            serde_json::from_value(params).map_err(|error| KwpError::BadRequest(error.to_string()))?;
        let response_artifact = NetResponseArtifactRequest::from_request(&request);
        if response_artifact.is_some() {
            self.ensure_artifacts_granted()?;
        }
        let mut validated = validate_net_fetch_request(grant, request)?;
        validated.response_byte_limit = reserve_net_request_in_meter(&mut self.net_access, grant, &validated.request)?;
        let mut result = fetch_net_blocking(validated)?;
        reserve_net_response_in_meter(&mut self.net_access, grant, &result)?;
        if let Some(response_artifact) = response_artifact {
            let body = result
                .body_base64
                .take()
                .map(|body| {
                    BASE64
                        .decode(body.as_bytes())
                        .map_err(|error| KwpError::Internal(error.to_string()))
                })
                .transpose()?
                .unwrap_or_default();
            result.artifact = Some(self.spill_net_response_artifact(response_artifact, &result.headers, &body)?);
        }
        serde_json::to_value(result).map_err(|error| KwpError::Internal(error.to_string()))
    }

    fn handle_bus_publish(&self, params: Value) -> Result<Value, KwpError> {
        let topic = params
            .get("topic")
            .and_then(Value::as_str)
            .ok_or_else(|| KwpError::BadRequest("bus topic omitted".to_string()))?;
        if topic.trim().is_empty() {
            return Err(KwpError::BadRequest("bus topic omitted".to_string()));
        }
        if !self.module.grant.bus.produce.iter().any(|pattern| pattern.matches(topic)) {
            return Err(KwpError::denied("bus.produce"));
        }
        let payload = params.get("payload").cloned().unwrap_or(Value::Null);
        self.record_bus_event(topic.to_string(), payload)?;
        Ok(serde_json::json!({ "published": true }))
    }

    fn scope_root(&self, scope: FsScope) -> Result<PathBuf, KwpError> {
        match scope {
            FsScope::Workspace | FsScope::Input => self
                .context
                .workspace
                .map(|workspace| workspace.root().to_path_buf())
                .ok_or_else(|| KwpError::denied("workspace")),
            FsScope::ModuleData => Ok(module_data_root(self.module, self.context)),
        }
    }

    fn verified_artifacts(
        &self,
        grant: &ArtifactsGrant,
        artifacts: Vec<ArtifactRef>,
    ) -> Result<Vec<ArtifactRef>, KwpError> {
        validate_artifact_refs(&artifacts)?;
        let root = self.artifact_root();
        verify_artifact_refs(&root, grant, artifacts)
    }

    fn verified_mcp_result(
        &self,
        grant: &McpGrant,
        mut result: McpCallResult,
    ) -> Result<McpCallResult, KwpError> {
        validate_mcp_result(result.clone())?;
        let artifact_grant = ArtifactsGrant {
            write: true,
            max_bytes_per_invocation: grant.max_artifacts_bytes_per_invocation,
        };
        result.artifacts = verify_artifact_refs(&self.artifact_root(), &artifact_grant, result.artifacts)?;
        Ok(result)
    }

    fn verified_fuzz_result(
        &self,
        grant: &FuzzGrant,
        mut result: FuzzRunResult,
    ) -> Result<FuzzRunResult, KwpError> {
        validate_fuzz_result(result.clone())?;
        let artifact_grant = self.fuzz_artifact_grant(grant)?;
        result.artifacts = verify_artifact_refs(&self.artifact_root(), &artifact_grant, result.artifacts)?;
        Ok(result)
    }

    fn fuzz_artifact_grant(&self, grant: &FuzzGrant) -> Result<ArtifactsGrant, KwpError> {
        let artifacts = self.required_artifact_grant()?;
        Ok(ArtifactsGrant {
            write: true,
            max_bytes_per_invocation: min_optional_u64(
                artifacts.max_bytes_per_invocation,
                grant.max_artifacts_bytes_per_invocation,
            ),
        })
    }

    fn ensure_fuzz_artifacts_granted(&self) -> Result<(), KwpError> {
        self.ensure_artifacts_granted()
    }

    fn ensure_artifacts_granted(&self) -> Result<(), KwpError> {
        self.required_artifact_grant().map(|_| ())
    }

    fn required_artifact_grant(&self) -> Result<&ArtifactsGrant, KwpError> {
        self.module
            .grant
            .artifacts
            .as_ref()
            .filter(|grant| grant.write)
            .ok_or_else(|| KwpError::denied("artifacts.write"))
    }

    fn spill_net_response_artifact(
        &self,
        request: NetResponseArtifactRequest,
        headers: &BTreeMap<String, String>,
        body: &[u8],
    ) -> Result<ArtifactRef, KwpError> {
        spill_net_response_artifact(
            &self.artifact_root(),
            self.required_artifact_grant()?,
            request,
            headers,
            body,
        )
    }

    fn reserve_mcp_call(
        &mut self,
        grant: &McpGrant,
        request: &McpCallRequest,
    ) -> Result<(), KwpError> {
        let used = self.mcp_calls.entry(request.alias.clone()).or_default();
        *used = used.saturating_add(1);
        check_count(*used, grant.max_calls_per_invocation, "mcp.calls")?;
        check_u64(
            request.limits.cpu_seconds,
            grant.max_cpu_seconds_per_invocation,
            "mcp.cpu_seconds",
        )?;
        check_u64(
            request.limits.artifact_bytes,
            grant.max_artifacts_bytes_per_invocation,
            "mcp.artifact_bytes",
        )
    }

    fn reserve_fuzz_job(
        &mut self,
        grant: &FuzzGrant,
        request: &FuzzRunRequest,
    ) -> Result<(), KwpError> {
        self.fuzz_jobs = self.fuzz_jobs.saturating_add(1);
        check_count(self.fuzz_jobs, grant.max_jobs_per_invocation, "fuzz.jobs")?;
        check_u64(
            request.limits.cpu_seconds,
            grant.max_cpu_seconds_per_invocation,
            "fuzz.cpu_seconds",
        )?;
        check_u64(
            request.limits.artifact_bytes,
            grant.max_artifacts_bytes_per_invocation,
            "fuzz.artifact_bytes",
        )
    }

    fn mcp_session(&self, alias: &str) -> McpSessionKey {
        McpSessionKey {
            alias: alias.to_string(),
            module_id: self.module.module_id.clone(),
            module_digest: self.module.digest.clone(),
            run_id: self.run_id.clone(),
            invocation_id: self.invocation_id.clone(),
        }
    }

    fn event_origin(&self) -> EventOrigin {
        EventOrigin {
            module_id: self.module.module_id.clone(),
            digest: self.module.digest.clone(),
            invocation_id: self.invocation_id.clone(),
        }
    }

    fn artifact_root(&self) -> PathBuf {
        self.context
            .workspace
            .map(|workspace| workspace.root().to_path_buf())
            .unwrap_or_else(|| module_data_root(self.module, self.context))
    }

    fn record_findings_run(&self, store: &crate::findings::FindingStore) -> Result<(), KwpError> {
        let target = self
            .context
            .workspace
            .map(|workspace| workspace.root())
            .unwrap_or(self.module.module_root.as_path());
        store
            .record_run_started(&self.run_id.0, target, "running")
            .map_err(|error| KwpError::Internal(error.to_string()))
    }

    fn record_invocation_start(&self) -> Result<(), KwpError> {
        self.record_audit(
            "invocation.start",
            AuditDecision::Allow,
            serde_json::json!({ "tool": self.tool_name }),
        )
    }

    fn record_invocation_end(&self, result: &Result<Value, KwpError>) -> Result<(), KwpError> {
        let (decision, detail) = match result {
            Ok(_) => (
                AuditDecision::Allow,
                serde_json::json!({
                    "tool": self.tool_name,
                    "runtimeCostUsd": self.runtime_cost_usd
                }),
            ),
            Err(error) => (
                AuditDecision::Deny,
                serde_json::json!({
                    "tool": self.tool_name,
                    "errorCode": error.code(),
                    "error": error.to_string(),
                    "runtimeCostUsd": self.runtime_cost_usd
                }),
            ),
        };
        self.record_audit("invocation.end", decision, detail)
    }

    fn record_invocation_cancel(&mut self, reason: &str) -> Result<(), KwpError> {
        if self.cancel_recorded {
            return Ok(());
        }
        self.record_audit(
            "invocation.cancel",
            AuditDecision::Deny,
            serde_json::json!({
                "tool": self.tool_name,
                "reason": reason,
            }),
        )?;
        self.cancel_recorded = true;
        Ok(())
    }

    fn record_broker_decision(&self, event: &str, result: &Result<Value, KwpError>) -> Result<(), KwpError> {
        let (decision, detail) = match result {
            Ok(_) => (AuditDecision::Allow, Value::Null),
            Err(error) => (
                AuditDecision::Deny,
                serde_json::json!({ "errorCode": error.code(), "error": error.to_string() }),
            ),
        };
        self.record_audit(event, decision, detail)
    }

    fn record_audit(
        &self,
        event: &str,
        decision: AuditDecision,
        detail: Value,
    ) -> Result<(), KwpError> {
        let Some(path) = self.audit_path() else {
            return Ok(());
        };
        let prev = last_kwp_audit_hash(&path)?;
        append_kwp_audit_log_record(
            &path,
            KwpAuditLogBody {
                ts_ms: now_unix_ms(),
                run_id: self.run_id.clone(),
                invocation_id: self.invocation_id.clone(),
                module_id: self.module.module_id.clone(),
                digest: self.module.digest.clone(),
                event: event.to_string(),
                decision,
                detail,
                prev,
            },
        )
        .map(|_| ())
    }

    fn record_bus_event(&self, topic: String, payload: Value) -> Result<(), KwpError> {
        let Some(path) = self.bus_path() else {
            return Err(KwpError::denied("bus.unavailable"));
        };
        append_kwp_bus_event(
            &path,
            KwpBusEvent {
                ts_ms: now_unix_ms(),
                run_id: self.run_id.clone(),
                invocation_id: self.invocation_id.clone(),
                module_id: self.module.module_id.clone(),
                digest: self.module.digest.clone(),
                topic,
                payload,
            },
        )
    }

    fn audit_path(&self) -> Option<PathBuf> {
        self.context
            .workspace
            .map(|workspace| kwp_audit_log_path(workspace.root(), &self.run_id.0))
    }

    fn bus_path(&self) -> Option<PathBuf> {
        self.context
            .workspace
            .map(|workspace| kwp_bus_log_path(workspace.root(), &self.run_id.0))
    }

    fn attach_host_metrics(&self, mut result: Value) -> Value {
        let Value::Object(ref mut object) = result else {
            return result;
        };
        let data = object
            .entry("data")
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Value::Object(data) = data {
            data.insert(
                "kwp".to_string(),
                serde_json::json!({
                    "runtimeCostUsd": self.runtime_cost_usd,
                    "invocationId": self.invocation_id.0,
                    "runId": self.run_id.0,
                    "moduleDigest": self.module.digest.0,
                }),
            );
        }
        result
    }
}

fn broker_audit_event(method: &str) -> String {
    match method {
        METHOD_FS_READ => "fs.read",
        METHOD_FS_WRITE => "fs.write",
        METHOD_FS_LIST => "fs.list",
        METHOD_FS_STAT => "fs.stat",
        METHOD_FS_REMOVE => "fs.remove",
        METHOD_RUNTIME_QUERY => "runtime.query",
        METHOD_ARTIFACTS_RECORD => "artifacts.record",
        METHOD_FINDINGS_CREATE => "findings.create",
        METHOD_MCP_CALL => "mcp.call",
        METHOD_FUZZ_RUN => "fuzz.run",
        METHOD_NET_FETCH => "net.fetch",
        METHOD_BUS_PUBLISH => "bus.publish",
        _ => "worker.request",
    }
    .to_string()
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WorkerFsReadRequest {
    scope: FsScope,
    path: String,
    offset: Option<u64>,
    length: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WorkerFsWriteRequest {
    scope: FsScope,
    path: String,
    data_base64: String,
    append: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WorkerFsPathRequest {
    scope: FsScope,
    path: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WorkerFindingInput {
    #[serde(default, alias = "rule_id")]
    rule_id: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default, alias = "file_path")]
    file_path: Option<String>,
    #[serde(default, alias = "start_line")]
    start_line: Option<u32>,
    #[serde(default, alias = "end_line")]
    end_line: Option<u32>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(default, alias = "actor_fingerprint")]
    actor_fingerprint: Option<String>,
    #[serde(default, alias = "static_proof_state")]
    static_proof_state: Option<crate::findings::StaticProofState>,
    #[serde(default)]
    remediation: Option<String>,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    evidence: Vec<crate::findings::FindingEvidence>,
    #[serde(default, alias = "dedup_key")]
    dedup_key: Option<String>,
    #[serde(default, alias = "source_signature")]
    source_signature: Option<String>,
    #[serde(default, alias = "vuln_source")]
    vuln_source: Option<crate::findings::VulnSource>,
}

fn module_data_root(module: &VerifiedModule, ctx: &crate::modules::ToolExecutionContext<'_>) -> PathBuf {
    let digest = module.digest.0.replace([':', '/', '\\'], "_");
    if let Some(workspace) = ctx.workspace {
        return workspace.state_dir().join("kwp").join("modules").join(digest);
    }
    module.module_root.join(".kuzushi").join("kwp").join(digest)
}

fn resolve_read_path(root: &Path, path: &str) -> Result<PathBuf, KwpError> {
    validate_relative_path(path).map_err(|_| KwpError::denied("fs.path"))?;
    let root = canonical_or_create_root(root)?;
    let candidate = root.join(path);
    let canonical = fs::canonicalize(&candidate).map_err(|error| KwpError::denied(format!("fs.path:{error}")))?;
    if canonical.starts_with(&root) {
        Ok(canonical)
    } else {
        Err(KwpError::denied("fs.path"))
    }
}

fn resolve_write_path(root: &Path, path: &str) -> Result<PathBuf, KwpError> {
    validate_relative_path(path).map_err(|_| KwpError::denied("fs.path"))?;
    let root = canonical_or_create_root(root)?;
    let candidate = root.join(path);
    if fs::symlink_metadata(&candidate)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(KwpError::denied("fs.path"));
    }
    let parent = candidate
        .parent()
        .ok_or_else(|| KwpError::denied("fs.path"))?;
    fs::create_dir_all(parent).map_err(|error| KwpError::Internal(error.to_string()))?;
    let parent = fs::canonicalize(parent).map_err(|error| KwpError::Internal(error.to_string()))?;
    if parent.starts_with(&root) {
        Ok(candidate)
    } else {
        Err(KwpError::denied("fs.path"))
    }
}

fn resolve_remove_path(root: &Path, path: &str) -> Result<PathBuf, KwpError> {
    validate_relative_path(path).map_err(|_| KwpError::denied("fs.path"))?;
    let root = canonical_or_create_root(root)?;
    let candidate = root.join(path);
    if fs::symlink_metadata(&candidate)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(KwpError::denied("fs.path"));
    }
    let canonical = fs::canonicalize(&candidate).map_err(|error| KwpError::denied(format!("fs.path:{error}")))?;
    if canonical.starts_with(&root) {
        Ok(canonical)
    } else {
        Err(KwpError::denied("fs.path"))
    }
}

fn canonical_or_create_root(root: &Path) -> Result<PathBuf, KwpError> {
    fs::create_dir_all(root).map_err(|error| KwpError::Internal(error.to_string()))?;
    fs::canonicalize(root).map_err(|error| KwpError::Internal(error.to_string()))
}

fn fs_list_entry(entry: fs::DirEntry) -> Result<Value, KwpError> {
    let file_type = entry.file_type().map_err(|error| KwpError::Internal(error.to_string()))?;
    let metadata = entry
        .metadata()
        .map_err(|error| KwpError::Internal(error.to_string()))?;
    Ok(serde_json::json!({
        "name": entry.file_name().to_string_lossy(),
        "kind": fs_kind(file_type.is_file(), file_type.is_dir()),
        "size": metadata.len(),
        "mtime": metadata_modified_ms(&metadata),
    }))
}

fn fs_metadata_json(metadata: &fs::Metadata) -> Value {
    serde_json::json!({
        "kind": fs_kind(metadata.is_file(), metadata.is_dir()),
        "size": metadata.len(),
        "mtime": metadata_modified_ms(metadata),
    })
}

fn fs_kind(is_file: bool, is_dir: bool) -> &'static str {
    if is_file {
        "file"
    } else if is_dir {
        "dir"
    } else {
        "other"
    }
}

fn metadata_modified_ms(metadata: &fs::Metadata) -> u128 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

fn slice_bytes(bytes: &[u8], offset: usize, length: Option<usize>) -> &[u8] {
    if offset >= bytes.len() {
        return &[];
    }
    let end = length
        .and_then(|length| offset.checked_add(length))
        .map(|end| end.min(bytes.len()))
        .unwrap_or(bytes.len());
    &bytes[offset..end]
}

fn artifacts_from_params(params: &Value) -> Result<Vec<ArtifactRef>, KwpError> {
    let artifacts = params
        .get("artifacts")
        .cloned()
        .ok_or_else(|| KwpError::BadRequest("artifacts omitted".to_string()))?;
    serde_json::from_value(artifacts).map_err(|error| KwpError::BadRequest(error.to_string()))
}

fn verify_artifact_refs(
    root: &Path,
    grant: &ArtifactsGrant,
    artifacts: Vec<ArtifactRef>,
) -> Result<Vec<ArtifactRef>, KwpError> {
    let mut total_bytes = 0_u64;
    artifacts
        .into_iter()
        .map(|artifact| verify_artifact_ref(root, grant, &mut total_bytes, artifact))
        .collect()
}

fn verify_artifact_ref(
    root: &Path,
    grant: &ArtifactsGrant,
    total_bytes: &mut u64,
    mut artifact: ArtifactRef,
) -> Result<ArtifactRef, KwpError> {
    if artifact.media_type.trim().is_empty() {
        return Err(KwpError::BadRequest("artifact mediaType omitted".to_string()));
    }
    let path = resolve_read_path(root, &artifact.path)?;
    let bytes = fs::read(&path).map_err(|error| KwpError::Internal(error.to_string()))?;
    *total_bytes = total_bytes
        .checked_add(bytes.len() as u64)
        .ok_or_else(|| KwpError::quota("artifacts.bytes"))?;
    if grant
        .max_bytes_per_invocation
        .is_some_and(|max| *total_bytes > max)
    {
        return Err(KwpError::quota("artifacts.bytes"));
    }
    let actual = sha256_digest(&bytes).0;
    if artifact.sha256.as_deref().is_some_and(|declared| declared != actual) {
        return Err(KwpError::denied("artifact.sha256"));
    }
    artifact.sha256 = Some(actual);
    Ok(artifact)
}

fn worker_findings_from_value(value: &Value, default_tool: &str) -> Result<Vec<crate::findings::Finding>, KwpError> {
    let Some(findings) = value.as_array() else {
        return Err(KwpError::BadRequest("findings must be an array".to_string()));
    };
    findings
        .iter()
        .cloned()
        .map(|finding| worker_finding_from_value(finding, default_tool))
        .collect()
}

fn worker_finding_from_value(value: Value, default_tool: &str) -> Result<crate::findings::Finding, KwpError> {
    let input: WorkerFindingInput =
        serde_json::from_value(value).map_err(|error| KwpError::BadRequest(error.to_string()))?;
    let file_path = required_text(input.file_path.clone(), "finding.filePath")?;
    let start_line = input.start_line.unwrap_or(1);
    let message = input
        .message
        .clone()
        .or_else(|| input.title.clone())
        .unwrap_or_else(|| "worker finding".to_string());
    let rule_id = input
        .rule_id
        .clone()
        .unwrap_or_else(|| format!("{default_tool}:finding"));
    let severity = worker_finding_severity(input.severity.clone())?;
    let mut finding = crate::findings::Finding::new_tool(
        default_tool,
        rule_id,
        file_path,
        start_line,
        input.end_line,
        severity,
        message,
    );
    apply_worker_finding_overrides(&mut finding, input);
    Ok(finding)
}

fn apply_worker_finding_overrides(
    finding: &mut crate::findings::Finding,
    input: WorkerFindingInput,
) {
    if let Some(value) = nonempty_text(input.title) {
        finding.title = value;
    }
    if let Some(value) = nonempty_text(input.fingerprint) {
        finding.fingerprint = value;
    }
    finding.actor_fingerprint = input.actor_fingerprint;
    finding.static_proof_state = input.static_proof_state;
    finding.remediation = input.remediation;
    finding.references = input.references;
    finding.evidence = input.evidence;
    finding.dedup_key = input.dedup_key.or(finding.dedup_key.take());
    finding.source_signature = input.source_signature.or(finding.source_signature.take());
    finding.vuln_source = input.vuln_source.or_else(|| finding.vuln_source.take());
}

fn required_text(value: Option<String>, field: &str) -> Result<String, KwpError> {
    nonempty_text(value).ok_or_else(|| KwpError::BadRequest(format!("{field} omitted")))
}

fn nonempty_text(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn worker_finding_severity(value: Option<String>) -> Result<crate::findings::Severity, KwpError> {
    let Some(value) = value else {
        return Ok(crate::findings::Severity::Unknown);
    };
    crate::findings::Severity::try_from(value.as_str())
        .map_err(|error| KwpError::BadRequest(error.to_string()))
}

fn ensure_finding_severities_allowed(
    grant: &FindingsGrant,
    findings: &[crate::findings::Finding],
) -> Result<(), KwpError> {
    if grant.allowed_severities.is_empty() {
        return Ok(());
    }
    if findings.iter().all(|finding| severity_allowed(grant, finding.severity)) {
        Ok(())
    } else {
        Err(KwpError::denied("findings.severity"))
    }
}

fn severity_allowed(grant: &FindingsGrant, severity: crate::findings::Severity) -> bool {
    grant
        .allowed_severities
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(severity.as_str()))
}

fn fetch_net_blocking(validated: ValidatedNetFetch) -> Result<NetFetchResult, KwpError> {
    let timeout = validated
        .request
        .timeout_ms
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_secs(30));
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .build()
        .map_err(|error| KwpError::Internal(error.to_string()))?;
    let method = reqwest::Method::from_bytes(validated.request.method.as_bytes())
        .map_err(|error| KwpError::BadRequest(error.to_string()))?;
    let mut request = client.request(method, &validated.request.url);
    for (name, value) in &validated.request.headers {
        let header_name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|error| KwpError::BadRequest(error.to_string()))?;
        let header_value = reqwest::header::HeaderValue::from_str(value)
            .map_err(|error| KwpError::BadRequest(error.to_string()))?;
        request = request.header(header_name, header_value);
    }
    if let Some(body) = validated.request.body_base64.as_ref() {
        let body = BASE64
            .decode(body.as_bytes())
            .map_err(|error| KwpError::BadRequest(error.to_string()))?;
        request = request.body(body);
    }
    let response = request
        .send()
        .map_err(|error| KwpError::Internal(error.to_string()))?;
    let status = response.status().as_u16();
    let headers = response_headers(response.headers());
    check_u64(response.content_length(), validated.response_byte_limit, "net.bytes")?;
    let body = read_net_response_body(response, validated.response_byte_limit)?;
    Ok(NetFetchResult {
        status,
        headers,
        body_base64: Some(BASE64.encode(body)),
        artifact: None,
    })
}

fn read_net_response_body<R: Read>(mut reader: R, limit: Option<u64>) -> Result<Vec<u8>, KwpError> {
    let mut body = Vec::new();
    if let Some(limit) = limit {
        let mut limited = reader.by_ref().take(limit.saturating_add(1));
        limited
            .read_to_end(&mut body)
            .map_err(|error| KwpError::Internal(error.to_string()))?;
        check_u64(Some(body.len() as u64), Some(limit), "net.bytes")?;
        return Ok(body);
    }
    reader
        .read_to_end(&mut body)
        .map_err(|error| KwpError::Internal(error.to_string()))?;
    Ok(body)
}

fn response_headers(headers: &reqwest::header::HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect()
}

pub struct WorkerSupervisor {
    trust: Arc<LockfileTrustVerifier>,
    executors: BTreeMap<ExecutorTier, Arc<dyn WorkerExecutor>>,
}

impl WorkerSupervisor {
    pub fn new(trust: Arc<LockfileTrustVerifier>, executors: BTreeMap<ExecutorTier, Arc<dyn WorkerExecutor>>) -> Self {
        Self { trust, executors }
    }

    pub async fn spawn_verified(&self, specifier: &str, mode: WorkerMode) -> Result<SpawnedWorker, KwpError> {
        let module = self
            .trust
            .verify(specifier)
            .await
            .map_err(|error| KwpError::denied(format!("trust.{error}")))?;
        let executor = self.executors.get(&module.tier).ok_or_else(|| KwpError::denied("executor"))?;
        executor.spawn(module, mode).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer as _;
    use serde_json::json;

    struct AllowSignatures;

    impl SignatureVerifier for AllowSignatures {
        fn verify_chain(&self, _entry: &LockfileEntry, _bundle: &WorkerBundle) -> bool {
            true
        }
    }

    struct FixedResolver(WorkerBundle);

    #[async_trait]
    impl BundleResolver for FixedResolver {
        async fn resolve(&self, _specifier: &str) -> Result<WorkerBundle, TrustError> {
            Ok(self.0.clone())
        }
    }

    #[derive(Default)]
    struct Effects {
        mcp_sessions: Mutex<Vec<McpSessionKey>>,
        fuzz_requests: Mutex<Vec<FuzzRunRequest>>,
        audit: Mutex<Vec<AuditRecord>>,
    }

    #[async_trait]
    impl FsBackend for Effects {
        async fn read(&self, _scope: FsScope, _path: &str, _offset: u64, _length: Option<u64>) -> Result<FsReadResult, KwpError> {
            Ok(FsReadResult { data: Vec::new(), eof: true })
        }

        async fn write(&self, _scope: FsScope, _path: &str, data: Vec<u8>, _append: bool) -> Result<u64, KwpError> {
            Ok(data.len() as u64)
        }
    }

    #[async_trait]
    impl NetBackend for Effects {
        async fn fetch(&self, _request: NetFetchRequest) -> Result<NetFetchResult, KwpError> {
            Ok(NetFetchResult { status: 200, headers: BTreeMap::new(), body_base64: None, artifact: None })
        }
    }

    #[async_trait]
    impl RuntimeBackend for Effects {
        async fn query(&self, _request: RuntimeQueryRequest) -> Result<RuntimeQueryResult, KwpError> {
            Ok(RuntimeQueryResult { completion: json!({}), cost_usd: 0.01 })
        }
    }

    #[async_trait]
    impl BusBackend for Effects {
        async fn publish(&self, _origin: EventOrigin, _topic: String, _payload: Value) -> Result<(), KwpError> {
            Ok(())
        }
    }

    #[async_trait]
    impl FindingBackend for Effects {
        async fn create(&self, _origin: EventOrigin, findings: Vec<Value>) -> Result<FindingsCreateResult, KwpError> {
            Ok(FindingsCreateResult { created: findings.len() })
        }
    }

    #[async_trait]
    impl ArtifactBackend for Effects {
        async fn record(&self, _origin: EventOrigin, artifacts: Vec<ArtifactRef>) -> Result<Vec<ArtifactRef>, KwpError> {
            validate_artifact_refs(&artifacts)?;
            Ok(artifacts)
        }
    }

    #[async_trait]
    impl McpBackend for Effects {
        async fn call(&self, session: McpSessionKey, _request: McpCallRequest) -> Result<McpCallResult, KwpError> {
            self.mcp_sessions.lock().await.push(session);
            Ok(McpCallResult { structured_content: json!({}), artifacts: Vec::new() })
        }
    }

    #[async_trait]
    impl FuzzBackend for Effects {
        async fn run(&self, _origin: EventOrigin, request: FuzzRunRequest) -> Result<FuzzRunResult, KwpError> {
            self.fuzz_requests.lock().await.push(request);
            Ok(FuzzRunResult::default())
        }
    }

    #[async_trait]
    impl AuditSink for Effects {
        async fn record(&self, record: AuditRecord) {
            self.audit.lock().await.push(record);
        }
    }

    fn invocation_for(module: &str, grant: Grant) -> InvocationAuthority {
        InvocationAuthority::new(
            ModuleId(module.to_string()),
            Digest(format!("sha256:{module}")),
            RunId("run_1".to_string()),
            InvocationId(format!("inv_{module}")),
            Arc::new(AtomicU64::new(0)),
            Arc::new(grant),
        )
    }

    fn broker(effects: Arc<Effects>) -> CapabilityBroker {
        let mut catalog = McpCatalog::default();
        catalog.insert(McpCatalogEntry {
            alias: "symcc".to_string(),
            descriptor_hash: "sha256:descriptor".to_string(),
            tools: BTreeMap::from([
                ("compile".to_string(), mcp_tool("compile")),
                ("export_corpus".to_string(), mcp_tool("export_corpus")),
            ]),
        });
        CapabilityBroker {
            fs: effects.clone(),
            net: effects.clone(),
            runtime: effects.clone(),
            bus: effects.clone(),
            findings: effects.clone(),
            artifacts: effects.clone(),
            mcp: effects.clone(),
            fuzz: effects.clone(),
            mcp_catalog: Arc::new(catalog),
            audit: effects,
        }
    }

    fn mcp_tool(name: &str) -> McpToolDescriptor {
        McpToolDescriptor {
            name: name.to_string(),
            description: name.to_string(),
            input_schema: json!({ "type": "object" }),
            output_schema: None,
        }
    }

    fn mcp_grant(tools: &[&str]) -> Grant {
        Grant {
            mcp: vec![McpGrant {
                alias: "symcc".to_string(),
                tools: tools.iter().map(|tool| (*tool).to_string()).collect(),
                mode: McpGrantMode::Shared,
                max_calls_per_invocation: None,
                max_cpu_seconds_per_invocation: None,
                max_bytes_per_invocation: None,
                max_artifacts_bytes_per_invocation: None,
                workspace: McpWorkspaceMode::ScratchOnly,
            }],
            ..Grant::default()
        }
    }

    fn mcp_request(module: &str, tool: &str) -> McpCallRequest {
        McpCallRequest {
            invocation_id: InvocationId(format!("inv_{module}")),
            alias: "symcc".to_string(),
            tool: tool.to_string(),
            arguments: json!({}),
            limits: McpCallLimits::default(),
        }
    }

    fn worker_bundle() -> WorkerBundle {
        WorkerBundle {
            specifier: "package:agentic-fuzz".to_string(),
            module_id: ModuleId("agentic-fuzz".to_string()),
            module_root: PathBuf::from("/tmp/module"),
            entry: "dist/index.js".to_string(),
            tier: ExecutorTier::Node,
            digest: Digest("sha256:abc".to_string()),
            descriptor_hash: "sha256:descriptor".to_string(),
        }
    }

    fn approved_entry(bundle: &WorkerBundle) -> LockfileEntry {
        LockfileEntry {
            module_id: bundle.module_id.clone(),
            digest: bundle.digest.clone(),
            version: "1.0.0".to_string(),
            descriptor_hash: bundle.descriptor_hash.clone(),
            grant: Grant::default(),
            signature_chain: Vec::new(),
            revoked: false,
        }
    }

    fn lockfile_with(entry: LockfileEntry) -> KuzushiLockfile {
        let mut lockfile = KuzushiLockfile::default();
        lockfile.approve(entry).unwrap();
        lockfile
    }

    #[tokio::test]
    async fn trust_verifier_pins_digest_to_lockfile_entry() {
        let bundle = worker_bundle();
        let lockfile = lockfile_with(approved_entry(&bundle));
        let verifier = LockfileTrustVerifier::new(Arc::new(lockfile), Arc::new(FixedResolver(bundle)), Arc::new(AllowSignatures));

        let verified = verifier.verify("package:agentic-fuzz").await.unwrap();

        assert_eq!(verified.digest, Digest("sha256:abc".to_string()));
        assert_eq!(verified.module_id, ModuleId("agentic-fuzz".to_string()));
        assert_eq!(verified.descriptor_hash, "sha256:descriptor");
    }

    #[tokio::test]
    async fn trust_verifier_rejects_revoked_lockfile_entry() {
        let bundle = worker_bundle();
        let mut entry = approved_entry(&bundle);
        entry.revoked = true;
        let verifier = LockfileTrustVerifier::new(Arc::new(lockfile_with(entry)), Arc::new(FixedResolver(bundle)), Arc::new(AllowSignatures));

        let error = verifier.verify("package:agentic-fuzz").await.unwrap_err();

        assert_eq!(error, TrustError::Revoked);
    }

    #[tokio::test]
    async fn trust_verifier_rejects_descriptor_hash_drift() {
        let bundle = worker_bundle();
        let mut entry = approved_entry(&bundle);
        entry.descriptor_hash = "sha256:old-descriptor".to_string();
        let verifier = LockfileTrustVerifier::new(Arc::new(lockfile_with(entry)), Arc::new(FixedResolver(bundle)), Arc::new(AllowSignatures));

        let error = verifier.verify("package:agentic-fuzz").await.unwrap_err();

        assert_eq!(error, TrustError::DescriptorHashMismatch);
    }

    #[test]
    fn lockfile_round_trips_json_and_validates_digest_keys() {
        let bundle = worker_bundle();
        let lockfile = lockfile_with(approved_entry(&bundle));
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("kuzushi.lock");

        lockfile.write_json(&path).unwrap();
        let read = KuzushiLockfile::read_json(&path).unwrap();

        assert_eq!(read, lockfile);
    }

    #[test]
    fn lockfile_rejects_digest_key_mismatch() {
        let bundle = worker_bundle();
        let mut lockfile = KuzushiLockfile::default();
        lockfile
            .modules
            .insert("sha256:wrong".to_string(), approved_entry(&bundle));

        let error = lockfile.write_json(tempfile::NamedTempFile::new().unwrap().path()).unwrap_err();

        assert_eq!(
            error,
            TrustError::LockfileDigestKeyMismatch {
                key: "sha256:wrong".to_string(),
                entry_digest: "sha256:abc".to_string(),
            }
        );
    }

    #[test]
    fn configured_signature_verifier_accepts_trusted_ed25519_chain() {
        let bundle = worker_bundle();
        let mut entry = approved_entry(&bundle);
        sign_entry(&mut entry);
        let verifier = ConfiguredSignatureVerifier::new(vec![signature_trust_key()]);

        verifier.verify_lockfile_entry(&entry).unwrap();
    }

    #[test]
    fn configured_signature_verifier_rejects_tampered_signature_payload() {
        let bundle = worker_bundle();
        let mut entry = approved_entry(&bundle);
        sign_entry(&mut entry);
        entry.descriptor_hash = "sha256:tampered".to_string();
        let verifier = ConfiguredSignatureVerifier::new(vec![signature_trust_key()]);

        let error = verifier.verify_lockfile_entry(&entry).unwrap_err();

        assert_eq!(error, SignatureVerificationError::InvalidSignature);
    }

    #[test]
    fn configured_signature_verifier_requires_trusted_key() {
        let bundle = worker_bundle();
        let mut entry = approved_entry(&bundle);
        sign_entry(&mut entry);
        let verifier = ConfiguredSignatureVerifier::default();

        let error = verifier.verify_lockfile_entry(&entry).unwrap_err();

        assert_eq!(error, SignatureVerificationError::MissingTrustedKeys);
    }

    fn sign_entry(entry: &mut LockfileEntry) {
        let payload = signature_payload_bytes(entry).unwrap();
        let signature = signing_key().sign(&payload);
        entry.signature_chain = vec![format!(
            "ed25519:v1:test-author:{}",
            BASE64.encode(signature.to_bytes())
        )];
    }

    fn signature_trust_key() -> SignatureTrustKey {
        SignatureTrustKey {
            key_id: "test-author".to_string(),
            algorithm: SignatureAlgorithm::Ed25519,
            public_key: BASE64.encode(signing_key().verifying_key().as_bytes()),
        }
    }

    fn signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7; 32])
    }

    #[test]
    fn sha256_digest_uses_sha256_prefix() {
        assert_eq!(
            sha256_digest(b"abc"),
            Digest("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_string())
        );
    }

    #[test]
    fn kwp_audit_log_integrity_detects_hash_tampering() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("kwp-audit.jsonl");
        let first = append_kwp_audit_log_record(&path, audit_body(None, "invocation.start")).unwrap();
        append_kwp_audit_log_record(&path, audit_body(Some(first.hash), "fs.write")).unwrap();
        let mut records = read_kwp_audit_log_path(&path).unwrap();

        let clean = kwp_audit_log_integrity(&records).unwrap();
        assert!(clean.ok, "{clean:?}");

        records[1].event = "net.fetch".to_string();
        let tampered = kwp_audit_log_integrity(&records).unwrap();

        assert!(!tampered.ok, "{tampered:?}");
        assert!(tampered.errors.iter().any(|error| error.field == "hash"));
    }

    fn audit_body(prev: Option<String>, event: &str) -> KwpAuditLogBody {
        KwpAuditLogBody {
            ts_ms: 1,
            run_id: RunId("run-audit".to_string()),
            invocation_id: InvocationId("inv-audit".to_string()),
            module_id: ModuleId("audit-module".to_string()),
            digest: Digest("sha256:audit".to_string()),
            event: event.to_string(),
            decision: AuditDecision::Allow,
            detail: Value::Null,
            prev,
        }
    }

    #[test]
    fn kwp_bus_log_appends_host_stamped_events() {
        let tmp = tempfile::tempdir().unwrap();
        let path = kwp_bus_log_path(tmp.path(), "run-bus");

        append_kwp_bus_event(&path, bus_event("topic.allowed", json!({ "ok": true }))).unwrap();

        let events = read_kwp_bus_log(tmp.path(), "run-bus").unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].run_id, RunId("run-bus".to_string()));
        assert_eq!(events[0].invocation_id, InvocationId("inv-bus".to_string()));
        assert_eq!(events[0].module_id, ModuleId("bus-module".to_string()));
        assert_eq!(events[0].digest, Digest("sha256:bus".to_string()));
        assert_eq!(events[0].topic, "topic.allowed");
        assert_eq!(events[0].payload, json!({ "ok": true }));
    }

    #[test]
    fn kwp_bus_log_rejects_non_file_target() {
        let tmp = tempfile::tempdir().unwrap();
        let path = kwp_bus_log_path(tmp.path(), "run-bus");
        fs::create_dir_all(&path).unwrap();

        let error = append_kwp_bus_event(&path, bus_event("topic.allowed", Value::Null)).unwrap_err();

        assert!(matches!(error, KwpError::Internal(message) if message.contains("target is not a file")));
    }

    fn bus_event(topic: &str, payload: Value) -> KwpBusEvent {
        KwpBusEvent {
            ts_ms: 1,
            run_id: RunId("run-bus".to_string()),
            invocation_id: InvocationId("inv-bus".to_string()),
            module_id: ModuleId("bus-module".to_string()),
            digest: Digest("sha256:bus".to_string()),
            topic: topic.to_string(),
            payload,
        }
    }

    #[test]
    fn net_fetch_rejects_metadata_ip_even_when_allowlisted() {
        let grant = net_grant(&["169.254.169.254:443"]);
        let request = net_request("https://169.254.169.254/latest/meta-data");

        let error = validate_net_fetch_request(&grant, request).unwrap_err();

        assert_eq!(error, KwpError::denied("net.ssr.host"));
    }

    #[test]
    fn net_fetch_rejects_private_ip_even_when_allowlisted() {
        let grant = net_grant(&["10.0.0.1:443"]);
        let request = net_request("https://10.0.0.1/private");

        let error = validate_net_fetch_request(&grant, request).unwrap_err();

        assert_eq!(error, KwpError::denied("net.ssr.ip"));
    }

    #[test]
    fn net_fetch_rejects_localhost_names() {
        let grant = net_grant(&["localhost:443"]);
        let request = net_request("https://localhost/");

        let error = validate_net_fetch_request(&grant, request).unwrap_err();

        assert_eq!(error, KwpError::denied("net.ssr.host"));
    }

    #[test]
    fn net_fetch_rejects_unapproved_named_credential() {
        let grant = net_grant(&["93.184.216.34:443"]);
        let request = NetFetchRequest {
            credential_name: Some("prod".to_string()),
            ..net_request("https://93.184.216.34/")
        };

        let error = validate_net_fetch_request(&grant, request).unwrap_err();

        assert_eq!(error, KwpError::denied("net.credential"));
    }

    #[test]
    fn net_fetch_strips_worker_supplied_secret_headers() {
        let grant = net_grant(&["93.184.216.34:443"]);
        let mut request = net_request("https://93.184.216.34/");
        request.headers.insert("Authorization".to_string(), "Bearer stolen".to_string());
        request.headers.insert("Cookie".to_string(), "sid=secret".to_string());
        request
            .headers
            .insert("X-Forwarded-For".to_string(), "127.0.0.1".to_string());
        request.headers.insert("Accept".to_string(), "application/json".to_string());

        let validated = validate_net_fetch_request(&grant, request).unwrap();

        assert_eq!(validated.request.headers.len(), 1);
        assert_eq!(
            validated.request.headers.get("Accept").map(String::as_str),
            Some("application/json")
        );
    }

    #[test]
    fn net_meter_enforces_cumulative_byte_budget() {
        let mut grant = net_grant(&["93.184.216.34:443"]);
        grant.max_bytes_per_invocation = Some(8);
        let mut meter = NetAccessMeter::default();
        let mut request = net_request("https://93.184.216.34/");
        request.body_base64 = Some(BASE64.encode(b"abc"));
        let result = NetFetchResult {
            status: 200,
            headers: BTreeMap::new(),
            body_base64: Some(BASE64.encode(b"de")),
            artifact: None,
        };

        let remaining = reserve_net_request_in_meter(&mut meter, &grant, &request).unwrap();
        reserve_net_response_in_meter(&mut meter, &grant, &result).unwrap();
        request.body_base64 = Some(BASE64.encode(b"fghi"));
        let error = reserve_net_request_in_meter(&mut meter, &grant, &request).unwrap_err();

        assert_eq!(remaining, Some(5));
        assert_eq!(error, KwpError::quota("net.bytes"));
    }

    #[test]
    fn net_meter_enforces_cumulative_request_budget() {
        let mut grant = net_grant(&["93.184.216.34:443"]);
        grant.max_requests_per_invocation = Some(1);
        let mut meter = NetAccessMeter::default();
        let request = net_request("https://93.184.216.34/");

        reserve_net_request_in_meter(&mut meter, &grant, &request).unwrap();
        let error = reserve_net_request_in_meter(&mut meter, &grant, &request).unwrap_err();

        assert_eq!(error, KwpError::quota("net.requests"));
    }

    #[test]
    fn net_response_body_reader_enforces_response_byte_limit() {
        let body = read_net_response_body(std::io::Cursor::new(b"abcdef".to_vec()), Some(3)).unwrap_err();

        assert_eq!(body, KwpError::quota("net.bytes"));
    }

    #[test]
    fn net_response_body_reader_allows_body_at_limit() {
        let body = read_net_response_body(std::io::Cursor::new(b"abc".to_vec()), Some(3)).unwrap();

        assert_eq!(body, b"abc");
    }

    #[test]
    fn net_response_artifact_spill_writes_and_hashes_body() {
        let tmp = tempfile::tempdir().unwrap();
        let grant = ArtifactsGrant {
            write: true,
            max_bytes_per_invocation: Some(64),
        };
        let headers = BTreeMap::from([("content-type".to_string(), "text/plain".to_string())]);

        let artifact = spill_net_response_artifact(
            tmp.path(),
            &grant,
            NetResponseArtifactRequest {
                path: "net/response.txt".to_string(),
                media_type: None,
            },
            &headers,
            b"brokered response",
        )
        .unwrap();

        assert_eq!(artifact.path, "net/response.txt");
        assert_eq!(artifact.media_type, "text/plain");
        assert_eq!(fs::read(tmp.path().join("net/response.txt")).unwrap(), b"brokered response");
        assert_eq!(artifact.sha256, Some(sha256_digest(b"brokered response").0));
    }

    #[test]
    fn net_response_artifact_spill_denies_escape_and_quota() {
        let tmp = tempfile::tempdir().unwrap();
        let grant = ArtifactsGrant {
            write: true,
            max_bytes_per_invocation: Some(3),
        };
        let headers = BTreeMap::new();

        let escape = spill_net_response_artifact(
            tmp.path(),
            &grant,
            NetResponseArtifactRequest {
                path: "../escape.txt".to_string(),
                media_type: Some("text/plain".to_string()),
            },
            &headers,
            b"ok",
        )
        .unwrap_err();
        let quota = spill_net_response_artifact(
            tmp.path(),
            &grant,
            NetResponseArtifactRequest {
                path: "net/too-large.txt".to_string(),
                media_type: Some("text/plain".to_string()),
            },
            &headers,
            b"toolong",
        )
        .unwrap_err();

        assert_eq!(escape, KwpError::denied("artifact.path"));
        assert_eq!(quota, KwpError::quota("artifacts.bytes"));
        assert!(!tmp.path().join("net/too-large.txt").exists());
    }

    #[tokio::test]
    async fn fs_write_enforces_byte_quota() {
        let effects = Arc::new(Effects::default());
        let broker = broker(effects);
        let inv = invocation_for(
            "fs-quota",
            Grant {
                fs: vec![FsScopeGrant {
                    scope: FsScope::Workspace,
                    mode: FsMode::Rw,
                    max_bytes: Some(3),
                    max_files: None,
                }],
                ..Grant::default()
            },
        );

        let error = broker
            .fs_write(&inv, FsScope::Workspace, "out.txt", b"toolong".to_vec())
            .await
            .unwrap_err();

        assert_eq!(error, KwpError::quota("fs.bytes"));
    }

    fn net_grant(patterns: &[&str]) -> NetGrant {
        NetGrant {
            allow: patterns
                .iter()
                .map(|pattern| HostPattern((*pattern).to_string()))
                .collect(),
            credentials: Vec::new(),
            max_requests_per_invocation: None,
            max_bytes_per_invocation: None,
        }
    }

    fn net_request(url: &str) -> NetFetchRequest {
        NetFetchRequest {
            method: "GET".to_string(),
            url: url.to_string(),
            headers: BTreeMap::new(),
            body_base64: None,
            timeout_ms: None,
            credential_name: None,
            response_artifact_path: None,
            response_media_type: None,
        }
    }

    #[test]
    fn rpc_request_uses_jsonrpc_wire_shape() {
        let line = encode_rpc_line(&RpcMessage::request(7, "initialize", json!({"grant": {}}))).unwrap();
        let decoded: Value = serde_json::from_slice(&line).unwrap();

        assert_eq!(
            decoded,
            json!({
                "jsonrpc": "2.0",
                "id": 7,
                "method": "initialize",
                "params": { "grant": {} },
            })
        );
        assert_eq!(
            decode_rpc_line(&line).unwrap(),
            RpcMessage::request(7, "initialize", json!({"grant": {}}))
        );
    }

    #[test]
    fn rpc_response_and_error_use_jsonrpc_wire_shape() {
        let ok_line = encode_rpc_line(&RpcMessage::response("req-1", json!({"ok": true}))).unwrap();
        let error_line = encode_rpc_line(&RpcMessage::error_response("req-2", KwpError::denied("mcp").into())).unwrap();

        assert_eq!(
            serde_json::from_slice::<Value>(&ok_line).unwrap(),
            json!({ "jsonrpc": "2.0", "id": "req-1", "result": { "ok": true } })
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&error_line).unwrap(),
            json!({
                "jsonrpc": "2.0",
                "id": "req-2",
                "error": { "code": -32031, "message": "capability not granted: mcp" },
            })
        );
    }

    #[test]
    fn rpc_notification_uses_jsonrpc_wire_shape() {
        let line = encode_rpc_line(&RpcMessage::notification(
            "notifications/cancelled",
            json!({"invocationId": "inv_1"}),
        ))
        .unwrap();

        assert_eq!(
            decode_rpc_line(&line).unwrap(),
            RpcMessage::notification("notifications/cancelled", json!({"invocationId": "inv_1"}))
        );
    }

    #[test]
    fn rpc_decode_rejects_non_jsonrpc_2() {
        let error = decode_rpc_line(br#"{"jsonrpc":"1.0","id":1,"method":"initialize"}"#).unwrap_err();

        assert_eq!(error, KwpError::BadRequest("jsonrpc version must be 2.0".to_string()));
    }

    #[test]
    fn worker_request_authority_requires_invocation_and_epoch() {
        let invocation = InvocationId("inv_1".to_string());

        assert_eq!(
            ensure_worker_request_authority(&json!({ "epoch": 1 }), &invocation, 1).unwrap_err(),
            KwpError::NoActiveInvocation
        );
        assert_eq!(
            ensure_worker_request_authority(&json!({ "invocationId": "inv_1" }), &invocation, 1)
                .unwrap_err(),
            KwpError::EpochStale
        );
        assert_eq!(
            ensure_worker_request_authority(
                &json!({ "invocationId": "inv_1", "epoch": 0 }),
                &invocation,
                1
            )
            .unwrap_err(),
            KwpError::EpochStale
        );
        ensure_worker_request_authority(
            &json!({ "invocationId": "inv_1", "epoch": 1 }),
            &invocation,
            1,
        )
        .unwrap();
    }

    #[tokio::test]
    async fn module_without_mcp_grant_cannot_call_mcp() {
        let effects = Arc::new(Effects::default());
        let broker = broker(effects.clone());
        let inv = invocation_for("agentic-fuzz", Grant::default());

        let error = broker.mcp_call(&inv, mcp_request("agentic-fuzz", "compile")).await.unwrap_err();

        assert_eq!(error, KwpError::denied("mcp"));
        assert!(effects.mcp_sessions.lock().await.is_empty());
        let audit = effects.audit.lock().await;
        assert!(
            audit.is_empty(),
            "denied MCP requests must not reach the host audit log"
        );
    }

    #[tokio::test]
    async fn mcp_grant_allows_only_listed_tools() {
        let effects = Arc::new(Effects::default());
        let broker = broker(effects.clone());
        let inv = invocation_for("binary-hunt", mcp_grant(&["compile"]));

        broker.mcp_call(&inv, mcp_request("binary-hunt", "compile")).await.unwrap();
        let error = broker.mcp_call(&inv, mcp_request("binary-hunt", "export_corpus")).await.unwrap_err();

        assert_eq!(error, KwpError::denied("mcp.tool"));
        assert_eq!(effects.mcp_sessions.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn shared_mcp_pool_uses_per_invocation_sessions() {
        let effects = Arc::new(Effects::default());
        let broker = broker(effects.clone());
        let binary = invocation_for("binary-hunt", mcp_grant(&["compile"]));
        let fuzz = invocation_for("agentic-fuzz", mcp_grant(&["compile"]));

        broker.mcp_call(&binary, mcp_request("binary-hunt", "compile")).await.unwrap();
        broker.mcp_call(&fuzz, mcp_request("agentic-fuzz", "compile")).await.unwrap();

        let sessions = effects.mcp_sessions.lock().await;
        assert_eq!(sessions.len(), 2);
        assert_ne!(sessions[0].invocation_id, sessions[1].invocation_id);
    }

    #[tokio::test]
    async fn fuzz_run_requires_fuzz_grant_and_allowed_engine() {
        let effects = Arc::new(Effects::default());
        let broker = broker(effects.clone());
        let inv = invocation_for(
            "agentic-fuzz",
            Grant {
                fuzz: Some(FuzzGrant {
                    engines: vec![FuzzEngine::CargoFuzz],
                    max_jobs_per_invocation: Some(1),
                    max_cpu_seconds_per_invocation: Some(30),
                    max_artifacts_bytes_per_invocation: Some(1024),
                    network: false,
                }),
                artifacts: Some(ArtifactsGrant {
                    write: true,
                    max_bytes_per_invocation: Some(1024),
                }),
                ..Grant::default()
            },
        );

        broker.fuzz_run(&inv, fuzz_request(FuzzEngine::CargoFuzz)).await.unwrap();
        let error = broker.fuzz_run(&inv, fuzz_request(FuzzEngine::Libfuzzer)).await.unwrap_err();

        assert_eq!(error, KwpError::denied("fuzz.engine"));
        assert_eq!(effects.fuzz_requests.lock().await.len(), 1);
    }

    fn fuzz_request(engine: FuzzEngine) -> FuzzRunRequest {
        FuzzRunRequest {
            invocation_id: InvocationId("inv_agentic-fuzz".to_string()),
            engine,
            target: FuzzTarget {
                language: "rust".to_string(),
                project_path: "src".to_string(),
                harness_path: "agentic-fuzz/harnesses/parser.rs".to_string(),
            },
            inputs: BTreeMap::new(),
            limits: FuzzLimits { cpu_seconds: Some(10), artifact_bytes: Some(128), ..FuzzLimits::default() },
            sandbox: FuzzSandbox::default(),
        }
    }

    #[test]
    fn artifact_path_escape_is_rejected() {
        assert!(validate_relative_path("agentic-fuzz/crashes/one").is_ok());
        assert!(validate_relative_path("../escape").is_err());
        assert!(validate_relative_path("/absolute").is_err());
        assert!(validate_relative_path("a//b").is_err());
    }
}

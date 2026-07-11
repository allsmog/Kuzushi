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
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex as StdMutex, OnceLock};
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
const KWP_CANCEL_POLL: Duration = Duration::from_millis(50);
const KWP_DEFAULT_MCP_TIMEOUT: Duration = Duration::from_secs(30);
const KWP_MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const KWP_MAX_FS_READ_BYTES: u64 = 64 * 1024 * 1024;
const KWP_MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
const KWP_MAX_NETWORK_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;
const KWP_MAX_RUNTIME_OUTPUT_TOKENS: u32 = 65_536;
const KWP_WORKER_EPOCH: u64 = 1;
const KWP_AUDIT_ANCHOR_FILE: &str = "kwp-audit.anchor.json";
static KWP_AUDIT_LOCK: OnceLock<StdMutex<()>> = OnceLock::new();

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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Grant {
    #[serde(default)]
    pub fs: Vec<FsScopeGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net: Option<NetGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<RuntimeGrant>,
    #[serde(default)]
    pub bus: BusGrant,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub findings: Option<FindingsGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<ArtifactsGrant>,
    #[serde(default)]
    pub mcp: Vec<McpGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fuzz: Option<FuzzGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<Vec<ExecGrant>>,
    #[serde(default)]
    pub init_capabilities: InitCapabilities,
}

impl Grant {
    pub fn fs_scope(&self, scope: FsScope) -> Option<&FsScopeGrant> {
        self.fs.iter().find(|grant| grant.scope == scope)
    }

    pub fn allows_fs_write(&self, scope: FsScope) -> bool {
        if scope == FsScope::Input {
            return false;
        }
        self.fs_scope(scope)
            .is_some_and(|grant| grant.mode == FsMode::Rw)
    }

    pub fn mcp_grant(&self, alias: &str) -> Option<&McpGrant> {
        self.mcp.iter().find(|grant| grant.alias == alias)
    }

    pub fn validate(&self) -> Result<(), TrustError> {
        validate_input_fs_grants(&self.fs)?;
        validate_mcp_grants(&self.mcp)?;
        validate_fuzz_grant(self.fuzz.as_ref())?;
        validate_exec_grants(self.exec.as_deref())?;
        validate_runtime_grant(self.runtime.as_ref())?;
        Ok(())
    }
}

fn validate_input_fs_grants(grants: &[FsScopeGrant]) -> Result<(), TrustError> {
    if grants
        .iter()
        .any(|grant| grant.scope == FsScope::Input && grant.mode == FsMode::Rw)
    {
        return Err(invalid_grant("input filesystem scope must be read-only"));
    }
    Ok(())
}

fn validate_mcp_grants(grants: &[McpGrant]) -> Result<(), TrustError> {
    if grants.iter().any(|grant| {
        grant.mode != McpGrantMode::Dedicated || grant.workspace != McpWorkspaceMode::ReadWrite
    }) {
        return Err(invalid_grant(
            "MCP grants currently require mode=dedicated and workspace=read-write",
        ));
    }
    Ok(())
}

fn validate_fuzz_grant(grant: Option<&FuzzGrant>) -> Result<(), TrustError> {
    if grant.is_some_and(|grant| grant.network) {
        return Err(invalid_grant(
            "fuzz network grants are not supported by the host sandbox",
        ));
    }
    Ok(())
}

fn validate_exec_grants(grants: Option<&[ExecGrant]>) -> Result<(), TrustError> {
    if grants.is_some_and(|grants| !grants.is_empty()) {
        return Err(invalid_grant(
            "exec grants are not supported by the Node worker host",
        ));
    }
    Ok(())
}

fn validate_runtime_grant(grant: Option<&RuntimeGrant>) -> Result<(), TrustError> {
    let Some(grant) = grant else {
        return Ok(());
    };
    validate_runtime_budget(grant.max_cost_usd_per_invocation, "maxCostUsdPerInvocation")?;
    validate_runtime_budget(grant.max_cost_usd_per_run, "maxCostUsdPerRun")
}

fn validate_runtime_budget(value: f64, field: &str) -> Result<(), TrustError> {
    if !value.is_finite() || value < 0.0 {
        return Err(invalid_grant(&format!(
            "runtime {field} must be finite and non-negative"
        )));
    }
    Ok(())
}

fn invalid_grant(message: &str) -> TrustError {
    TrustError::LockfileInvalid(message.to_string())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    #[serde(alias = "moduleData")]
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
            let host = host.to_ascii_lowercase();
            let suffix = suffix.to_ascii_lowercase();
            return host
                .strip_suffix(&suffix)
                .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1);
        }
        pattern_host.eq_ignore_ascii_case(host)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeGrant {
    pub max_cost_usd_per_invocation: f64,
    pub max_cost_usd_per_run: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub models: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingsGrant {
    pub create: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_per_invocation: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_severities: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactsGrant {
    pub write: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes_per_invocation: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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

fn ensure_supported_mcp_grant(grant: &McpGrant) -> Result<(), KwpError> {
    if grant.mode != McpGrantMode::Dedicated {
        return Err(KwpError::denied("mcp.mode"));
    }
    if grant.workspace != McpWorkspaceMode::ReadWrite {
        return Err(KwpError::denied("mcp.workspace"));
    }
    Ok(())
}

fn apply_mcp_grant_limits(grant: &McpGrant, limits: &mut McpCallLimits) {
    let grant_deadline_ms = grant
        .max_cpu_seconds_per_invocation
        .and_then(|seconds| seconds.checked_mul(1_000));
    limits.deadline_ms = min_optional_u64(limits.deadline_ms, grant_deadline_ms);
    limits.artifact_bytes = min_optional_u64(
        limits.artifact_bytes,
        grant.max_artifacts_bytes_per_invocation,
    );
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

    async fn remaining_fs_bytes(&self, grant: &FsScopeGrant) -> u64 {
        remaining_fs_bytes(&self.meter.lock().await.fs, grant)
    }

    async fn reserve_net_request(
        &self,
        grant: &NetGrant,
        request: &NetFetchRequest,
    ) -> Result<Option<u64>, KwpError> {
        let mut meter = self.meter.lock().await;
        reserve_net_request_in_meter(&mut meter.net, grant, request)
    }

    async fn reserve_net_response(
        &self,
        grant: &NetGrant,
        result: &NetFetchResult,
    ) -> Result<(), KwpError> {
        let mut meter = self.meter.lock().await;
        reserve_net_response_in_meter(&mut meter.net, grant, result)
    }

    async fn reserve_mcp_call(
        &self,
        grant: &McpGrant,
        limits: &McpCallLimits,
    ) -> Result<(), KwpError> {
        let mut meter = self.meter.lock().await;
        meter.mcp_calls += 1;
        check_count(meter.mcp_calls, grant.max_calls_per_invocation, "mcp.calls")?;
        check_u64(
            limits.cpu_seconds,
            grant.max_cpu_seconds_per_invocation,
            "mcp.cpu_seconds",
        )?;
        check_u64(
            limits.artifact_bytes,
            grant.max_artifacts_bytes_per_invocation,
            "mcp.artifact_bytes",
        )?;
        Ok(())
    }

    async fn reserve_mcp_result(
        &self,
        grant: &McpGrant,
        result: &McpCallResult,
    ) -> Result<(), KwpError> {
        let bytes = serde_json::to_vec(result)
            .map_err(|error| KwpError::Internal(error.to_string()))?
            .len() as u64;
        let mut meter = self.meter.lock().await;
        meter.mcp_bytes = meter
            .mcp_bytes
            .checked_add(bytes)
            .ok_or_else(|| KwpError::quota("mcp.bytes"))?;
        check_u64(
            Some(meter.mcp_bytes),
            grant.max_bytes_per_invocation,
            "mcp.bytes",
        )
    }

    async fn reserve_fuzz_job(
        &self,
        grant: &FuzzGrant,
        request: &FuzzRunRequest,
    ) -> Result<(), KwpError> {
        let mut meter = self.meter.lock().await;
        meter.fuzz_jobs += 1;
        check_count(meter.fuzz_jobs, grant.max_jobs_per_invocation, "fuzz.jobs")?;
        check_u64(
            request.limits.cpu_seconds,
            grant.max_cpu_seconds_per_invocation,
            "fuzz.cpu_seconds",
        )?;
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
    mcp_bytes: u64,
    fuzz_jobs: u32,
}

#[derive(Default)]
struct FsAccessMeter {
    bytes_by_scope: BTreeMap<FsScope, u64>,
    files: BTreeSet<(FsScope, String)>,
}

fn reserve_fs_access_in_meter(
    meter: &mut FsAccessMeter,
    grant: &FsScopeGrant,
    path: &str,
    bytes: u64,
) -> Result<(), KwpError> {
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

fn remaining_fs_bytes(meter: &FsAccessMeter, grant: &FsScopeGrant) -> u64 {
    let used = meter.bytes_by_scope.get(&grant.scope).copied().unwrap_or(0);
    grant
        .max_bytes
        .map(|max| max.saturating_sub(used))
        .unwrap_or(KWP_MAX_FS_READ_BYTES)
        .min(KWP_MAX_FS_READ_BYTES)
}

#[derive(Default)]
struct NetAccessMeter {
    requests: u32,
    bytes: u64,
}

fn reserve_net_request_in_meter(
    meter: &mut NetAccessMeter,
    grant: &NetGrant,
    request: &NetFetchRequest,
) -> Result<Option<u64>, KwpError> {
    meter.requests = meter.requests.saturating_add(1);
    check_count(
        meter.requests,
        grant.max_requests_per_invocation,
        "net.requests",
    )?;
    let request_bytes = net_request_body_len(request)?;
    reserve_net_bytes_in_meter(meter, grant, request_bytes)?;
    Ok(remaining_net_bytes(meter, grant))
}

fn reserve_net_response_in_meter(
    meter: &mut NetAccessMeter,
    grant: &NetGrant,
    result: &NetFetchResult,
) -> Result<(), KwpError> {
    reserve_net_bytes_in_meter(meter, grant, net_result_body_len(result)?)
}

fn reserve_net_bytes_in_meter(
    meter: &mut NetAccessMeter,
    grant: &NetGrant,
    bytes: u64,
) -> Result<(), KwpError> {
    meter.bytes = meter
        .bytes
        .checked_add(bytes)
        .ok_or_else(|| KwpError::quota("net.bytes"))?;
    check_u64(
        Some(meter.bytes),
        grant.max_bytes_per_invocation,
        "net.bytes",
    )
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
    if path.split('/').any(|segment| {
        segment.is_empty() || segment == "." || segment == ".." || segment.contains('\\')
    }) {
        return Err(PathValidationError);
    }
    Ok(())
}

fn validate_broker_fs_path(scope: FsScope, path: &str) -> Result<(), KwpError> {
    validate_relative_path(path).map_err(|_| KwpError::denied("fs.path"))?;
    if scope == FsScope::Workspace
        && (path == "kuzushi.lock" || path == ".kuzushi" || path.starts_with(".kuzushi/"))
    {
        return Err(KwpError::denied("fs.control_path"));
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
        let lockfile: Self =
            serde_json::from_slice(&bytes).map_err(|error| TrustError::LockfileParse {
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
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| TrustError::LockfileSerialize(error.to_string()))?;
        crate::fs_atomic::write_atomic_bytes(path, &bytes).map_err(|error| TrustError::LockfileIo {
            path: path.to_path_buf(),
            error: error.to_string(),
        })
    }

    pub fn approve(&mut self, entry: LockfileEntry) -> Result<(), TrustError> {
        if entry.digest.0.trim().is_empty() {
            return Err(TrustError::LockfileInvalid(
                "module digest must not be empty".to_string(),
            ));
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
            entry.grant.validate()?;
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
    let bytes = serde_json::to_vec(value)
        .map_err(|error| TrustError::LockfileInvalid(error.to_string()))?;
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

fn resolved_file_bundle(
    specifier: &str,
    file: PathBuf,
) -> Result<ResolvedWorkerBundle, TrustError> {
    let root = file
        .parent()
        .ok_or_else(|| TrustError::BundlePathInvalid(format!("{} has no parent", file.display())))?
        .to_path_buf();
    let entry = file
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            TrustError::BundlePathInvalid(format!("{} has no UTF-8 file name", file.display()))
        })?
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

fn resolved_directory_bundle(
    specifier: &str,
    root: PathBuf,
) -> Result<ResolvedWorkerBundle, TrustError> {
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

fn hash_directory_entries(
    root: &Path,
    dir: &Path,
    hasher: &mut sha2::Sha256,
) -> Result<(), TrustError> {
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

fn hash_one_bundle_file(
    root: &Path,
    file: &Path,
    hasher: &mut sha2::Sha256,
) -> Result<(), TrustError> {
    let relative = file
        .strip_prefix(root)
        .map_err(|error| TrustError::BundlePathInvalid(error.to_string()))?;
    let relative = relative.to_str().ok_or_else(|| {
        TrustError::BundlePathInvalid(format!("{} is not UTF-8", relative.display()))
    })?;
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

    pub fn verify_lockfile_entry(
        &self,
        entry: &LockfileEntry,
    ) -> Result<(), SignatureVerificationError> {
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

    fn verify_signature_entry(
        &self,
        raw: &str,
        payload: &[u8],
    ) -> Result<(), SignatureVerificationError> {
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
        if key_id.trim().is_empty()
            || key_id.contains(':')
            || signature.trim().is_empty()
            || signature.contains(':')
        {
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
    grant: &'a Grant,
}

fn signature_payload_bytes(entry: &LockfileEntry) -> Result<Vec<u8>, SignatureVerificationError> {
    serde_json::to_vec(&SignaturePayload {
        domain: "kuzushi-kwp-signature-v1",
        module_id: &entry.module_id,
        digest: &entry.digest,
        descriptor_hash: &entry.descriptor_hash,
        version: &entry.version,
        grant: &entry.grant,
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

fn decode_ed25519_public_key(
    key: &SignatureTrustKey,
) -> Result<ed25519_dalek::VerifyingKey, SignatureVerificationError> {
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
    pub fn new(
        lockfile: Arc<KuzushiLockfile>,
        resolver: Arc<dyn BundleResolver>,
        signatures: Arc<dyn SignatureVerifier>,
    ) -> Self {
        Self {
            lockfile,
            resolver,
            signatures,
        }
    }

    pub async fn verify(&self, specifier: &str) -> Result<VerifiedModule, TrustError> {
        let bundle = self.resolver.resolve(specifier).await?;
        let entry = self
            .lockfile
            .entry_for_digest(&bundle.digest)
            .ok_or(TrustError::NotInLockfile)?;
        entry.grant.validate()?;
        ensure_entry_not_revoked(entry)?;
        ensure_entry_module_matches(entry, &bundle)?;
        ensure_entry_descriptor_matches(entry, &bundle)?;
        ensure_entry_signature(self.signatures.as_ref(), entry, &bundle)?;
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

fn ensure_entry_not_revoked(entry: &LockfileEntry) -> Result<(), TrustError> {
    if entry.revoked {
        return Err(TrustError::Revoked);
    }
    Ok(())
}

fn ensure_entry_module_matches(
    entry: &LockfileEntry,
    bundle: &WorkerBundle,
) -> Result<(), TrustError> {
    if entry.module_id != bundle.module_id {
        return Err(TrustError::ModuleIdMismatch);
    }
    Ok(())
}

fn ensure_entry_descriptor_matches(
    entry: &LockfileEntry,
    bundle: &WorkerBundle,
) -> Result<(), TrustError> {
    if entry.descriptor_hash != bundle.descriptor_hash {
        return Err(TrustError::DescriptorHashMismatch);
    }
    Ok(())
}

fn ensure_entry_signature(
    verifier: &dyn SignatureVerifier,
    entry: &LockfileEntry,
    bundle: &WorkerBundle,
) -> Result<(), TrustError> {
    if !verifier.verify_chain(entry, bundle) {
        return Err(TrustError::BadSignature);
    }
    Ok(())
}

#[async_trait]
pub trait FsBackend: Send + Sync {
    async fn read(
        &self,
        scope: FsScope,
        path: &str,
        offset: u64,
        length: Option<u64>,
    ) -> Result<FsReadResult, KwpError>;
    async fn write(
        &self,
        scope: FsScope,
        path: &str,
        data: Vec<u8>,
        append: bool,
    ) -> Result<u64, KwpError>;
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
    async fn publish(
        &self,
        origin: EventOrigin,
        topic: String,
        payload: Value,
    ) -> Result<(), KwpError>;
}

#[async_trait]
pub trait FindingBackend: Send + Sync {
    async fn create(
        &self,
        origin: EventOrigin,
        findings: Vec<Value>,
    ) -> Result<FindingsCreateResult, KwpError>;
}

#[async_trait]
pub trait ArtifactBackend: Send + Sync {
    async fn record(
        &self,
        origin: EventOrigin,
        artifacts: Vec<ArtifactRef>,
    ) -> Result<Vec<ArtifactRef>, KwpError>;
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
    async fn call(
        &self,
        session: McpSessionKey,
        request: McpCallRequest,
    ) -> Result<McpCallResult, KwpError>;
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
    timeout_ms: Option<u64>,
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
            timeout_ms: config.timeout_ms,
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
        let timeout = mcp_call_timeout(self.timeout_ms, request.limits.deadline_ms);
        let mut client = McpStdioClient::spawn(self, &session, timeout)?;
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

fn mcp_call_timeout(mount_ms: Option<u64>, request_ms: Option<u64>) -> Duration {
    let default_ms = KWP_DEFAULT_MCP_TIMEOUT.as_millis() as u64;
    let timeout_ms = match (mount_ms, request_ms) {
        (Some(mount), Some(request)) => mount.min(request),
        (Some(timeout), None) | (None, Some(timeout)) => timeout,
        (None, None) => default_ms,
    };
    Duration::from_millis(timeout_ms.max(1))
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
    stdout: mpsc::Receiver<Result<Option<Vec<u8>>, KwpError>>,
    next_id: u64,
    deadline: Instant,
}

impl McpStdioClient {
    fn spawn(
        mount: &StdioMcpMount,
        session: &McpSessionKey,
        timeout: Duration,
    ) -> Result<Self, KwpError> {
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
            stdout: spawn_mcp_stdout_reader(stdout, &mount.alias),
            next_id: 1,
            deadline: Instant::now()
                .checked_add(timeout)
                .unwrap_or_else(|| Instant::now() + KWP_DEFAULT_MCP_TIMEOUT),
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
        loop {
            let line = self.recv_stdout_line()?;
            let line = std::str::from_utf8(&line)
                .map_err(|error| KwpError::BadRequest(error.to_string()))?;
            if let Some(response) = matching_mcp_response(line, expected_id)? {
                return Ok(response);
            }
        }
    }

    fn recv_stdout_line(&self) -> Result<Vec<u8>, KwpError> {
        let timeout = remaining_mcp_time(self.deadline)?;
        match self.stdout.recv_timeout(timeout) {
            Ok(Ok(Some(line))) => Ok(line),
            Ok(Ok(None)) => Err(KwpError::Internal(format!(
                "MCP {} closed stdout",
                self.alias
            ))),
            Ok(Err(error)) => Err(error),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(KwpError::Deadline),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(KwpError::Internal(format!(
                "MCP {} stdout reader disconnected",
                self.alias
            ))),
        }
    }
}

impl Drop for McpStdioClient {
    fn drop(&mut self) {
        let _ = write_mcp_rpc(&mut self.stdin, 999_999, "shutdown", Value::Null);
        kill_kwp_child_process(&mut self.child);
        let _ = self.child.wait();
    }
}

fn remaining_mcp_time(deadline: Instant) -> Result<Duration, KwpError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(KwpError::Deadline)
}

fn spawn_mcp_stdout_reader(
    stdout: std::process::ChildStdout,
    alias: &str,
) -> mpsc::Receiver<Result<Option<Vec<u8>>, KwpError>> {
    let (sender, receiver) = mpsc::channel();
    let label = format!("MCP {alias} stdout");
    thread::spawn(move || read_mcp_stdout(stdout, &label, sender));
    receiver
}

fn read_mcp_stdout(
    stdout: std::process::ChildStdout,
    label: &str,
    sender: mpsc::Sender<Result<Option<Vec<u8>>, KwpError>>,
) {
    let mut reader = BufReader::new(stdout);
    loop {
        let line = read_bounded_line(&mut reader, label, "mcp.message_bytes");
        let done = !line.as_ref().is_ok_and(|line| line.is_some());
        if sender.send(line).is_err() || done {
            return;
        }
    }
}

fn spawn_mcp_process(mount: &StdioMcpMount, session: &McpSessionKey) -> Result<Child, KwpError> {
    let Some((program, args)) = mount.command.split_first() else {
        return Err(KwpError::BadRequest(
            "MCP mount command omitted".to_string(),
        ));
    };
    let mut command = Command::new(program);
    command.args(args).current_dir(&mount.cwd);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    sanitize_mcp_environment(&mut command, session);
    configure_kwp_process_group(&mut command);
    command.spawn().map_err(|error| {
        KwpError::Internal(format!(
            "could not start MCP alias {}: {error}",
            mount.alias
        ))
    })
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
    enforce_message_size(line.len(), "mcp.message_bytes")?;
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
        Self {
            network: false,
            read_only_source: true,
        }
    }
}

fn default_true() -> bool {
    true
}

fn validate_fuzz_request_paths(request: &FuzzRunRequest) -> Result<(), KwpError> {
    validate_fuzz_project_path(&request.target.project_path)?;
    validate_relative_path(&request.target.harness_path)
        .map_err(|_| KwpError::denied("fuzz.harnessPath"))?;
    for (key, value) in &request.inputs {
        if is_path_like_fuzz_input(key) {
            validate_relative_path(value).map_err(|_| KwpError::denied("fuzz.inputPath"))?;
        }
    }
    Ok(())
}

fn validate_fuzz_project_path(path: &str) -> Result<(), KwpError> {
    if path == "." {
        return Ok(());
    }
    validate_relative_path(path).map_err(|_| KwpError::denied("fuzz.projectPath"))
}

fn resolve_fuzz_project_path(root: &Path, path: &str) -> Result<PathBuf, KwpError> {
    if path == "." {
        return canonical_or_create_root(root);
    }
    resolve_read_path(root, path)
}

fn validate_fuzz_execution_request(request: &FuzzRunRequest) -> Result<(), KwpError> {
    if request.sandbox.network {
        return Err(KwpError::denied("fuzz.network"));
    }
    if !request.sandbox.read_only_source {
        return Err(KwpError::denied("fuzz.source_write"));
    }
    if request.limits.memory_bytes.is_some() {
        return Err(KwpError::denied("fuzz.memory_limit"));
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
    async fn run(
        &self,
        origin: EventOrigin,
        request: FuzzRunRequest,
    ) -> Result<FuzzRunResult, KwpError>;
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
    async fn run(
        &self,
        origin: EventOrigin,
        request: FuzzRunRequest,
    ) -> Result<FuzzRunResult, KwpError> {
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
        let stdout = tempfile::NamedTempFile::new()
            .map_err(|error| KwpError::Internal(error.to_string()))?;
        let stderr = tempfile::NamedTempFile::new()
            .map_err(|error| KwpError::Internal(error.to_string()))?;
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
        let output = fs::read_to_string(stdout.path())
            .map_err(|error| KwpError::Internal(error.to_string()))?;
        parse_fuzz_output(output, stderr)
    }
}

fn fuzz_executor_payload(
    workspace_root: &Path,
    origin: &EventOrigin,
    request: &FuzzRunRequest,
) -> Result<Value, KwpError> {
    let project_path = resolve_fuzz_project_path(workspace_root, &request.target.project_path)?;
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
        return Err(KwpError::BadRequest(
            "fuzz executor command omitted".to_string(),
        ));
    };
    let mut command = Command::new(program);
    command.args(args).current_dir(workspace_root);
    command.stdin(Stdio::piped());
    command.stdout(
        stdout
            .reopen()
            .map_err(|error| KwpError::Internal(error.to_string()))?,
    );
    command.stderr(
        stderr
            .reopen()
            .map_err(|error| KwpError::Internal(error.to_string()))?,
    );
    sanitize_fuzz_environment(&mut command, origin);
    configure_kwp_process_group(&mut command);
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
    serde_json::to_writer(&mut stdin, payload)
        .map_err(|error| KwpError::Internal(error.to_string()))?;
    stdin
        .write_all(b"\n")
        .map_err(|error| KwpError::Internal(error.to_string()))
}

fn fuzz_timeout(mount: &FuzzExecutorMount, request: &FuzzRunRequest) -> Duration {
    let cpu_ms = request
        .limits
        .cpu_seconds
        .and_then(|seconds| seconds.checked_mul(1_000));
    let timeout_ms = min_optional_u64(
        min_optional_u64(request.limits.deadline_ms, mount.timeout_ms),
        cpu_ms,
    )
    .unwrap_or(60_000);
    Duration::from_millis(timeout_ms.max(1))
}

fn wait_for_fuzz_process(child: &mut Child, timeout: Duration) -> Result<bool, KwpError> {
    let start = Instant::now();
    loop {
        if child
            .try_wait()
            .map_err(|error| KwpError::Internal(error.to_string()))?
            .is_some()
        {
            return Ok(true);
        }
        if start.elapsed() >= timeout {
            kill_kwp_child_process(child);
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
        .map_err(|error| {
            KwpError::Internal(format!(
                "fuzz executor returned invalid JSON: {error}; stderr={stderr}"
            ))
        })
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KwpAuditAnchor {
    record_count: u64,
    last_hash: String,
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

fn checked_kwp_run_artifact_path(
    target: &Path,
    run_id: &str,
    artifact: &str,
) -> Result<PathBuf, KwpError> {
    validate_kwp_run_id(run_id)?;
    validate_relative_path(artifact).map_err(|_| KwpError::denied("audit.path"))?;
    let root = crate::run_artifacts::runs_root(target);
    let path = root.join(run_id).join(artifact);
    ensure_no_symlink_components(&root, &path).map_err(|error| {
        KwpError::Internal(format!(
            "KWP audit path contains a symlink or invalid component: {error}"
        ))
    })?;
    Ok(path)
}

fn writable_kwp_run_artifact_path(
    target: &Path,
    run_id: &str,
    artifact: &str,
) -> Result<PathBuf, KwpError> {
    let path = checked_kwp_run_artifact_path(target, run_id, artifact)?;
    let parent = path
        .parent()
        .ok_or_else(|| KwpError::Internal("KWP run artifact has no parent".to_string()))?;
    fs::create_dir_all(parent).map_err(|error| KwpError::Internal(error.to_string()))?;
    checked_kwp_run_artifact_path(target, run_id, artifact)
}

fn validate_kwp_run_id(run_id: &str) -> Result<(), KwpError> {
    let mut chars = run_id.chars();
    if run_id.is_empty()
        || run_id.len() > 200
        || !chars.next().is_some_and(|ch| ch.is_ascii_alphanumeric())
        || !chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(KwpError::denied("audit.runId"));
    }
    Ok(())
}

pub fn kwp_bus_log_path(target: impl AsRef<Path>, run_id: &str) -> PathBuf {
    crate::run_artifacts::run_artifact_path(target, run_id, "kwp-bus.jsonl")
}

pub fn read_kwp_audit_log(
    target: impl AsRef<Path>,
    run_id: &str,
) -> Result<Vec<KwpAuditLogRecord>, KwpError> {
    let target = target.as_ref();
    let path = checked_kwp_run_artifact_path(target, run_id, "kwp-audit.jsonl")?;
    let anchor = checked_kwp_run_artifact_path(target, run_id, KWP_AUDIT_ANCHOR_FILE)?;
    read_anchored_kwp_audit_log(&path, &anchor)
}

pub fn read_kwp_bus_log(
    target: impl AsRef<Path>,
    run_id: &str,
) -> Result<Vec<KwpBusEvent>, KwpError> {
    let target = target.as_ref();
    let path = checked_kwp_run_artifact_path(target, run_id, "kwp-bus.jsonl")?;
    let text = fs::read_to_string(&path).map_err(|error| {
        KwpError::Internal(format!(
            "could not read KWP bus log {}: {error}",
            path.display()
        ))
    })?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line).map_err(|error| {
                KwpError::Internal(format!(
                    "could not parse KWP bus log {}: {error}",
                    path.display()
                ))
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
    let body = fs::read_to_string(path).map_err(|error| {
        KwpError::Internal(format!(
            "could not read KWP audit log {}: {error}",
            path.display()
        ))
    })?;
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line).map_err(|error| {
                KwpError::Internal(format!(
                    "could not parse KWP audit log {}: {error}",
                    path.display()
                ))
            })
        })
        .collect()
}

fn read_anchored_kwp_audit_log(
    path: &Path,
    anchor_path: &Path,
) -> Result<Vec<KwpAuditLogRecord>, KwpError> {
    let log_exists = path_exists_without_follow(path)?;
    let anchor_exists = path_exists_without_follow(anchor_path)?;
    match (log_exists, anchor_exists) {
        (false, false) => return Ok(Vec::new()),
        (false, true) => {
            return Err(KwpError::Internal(
                "KWP audit log is missing but its integrity anchor remains".to_string(),
            ))
        }
        (true, false) => {
            return Err(KwpError::Internal(
                "KWP audit integrity anchor is missing".to_string(),
            ))
        }
        (true, true) => {}
    }

    let records = read_kwp_audit_log_path(path)?;
    let integrity = kwp_audit_log_integrity(&records)?;
    if !integrity.ok {
        return Err(KwpError::Internal(
            "KWP audit hash chain failed integrity validation".to_string(),
        ));
    }
    let anchor = read_kwp_audit_anchor(anchor_path)?;
    let expected_count = records.len() as u64;
    let expected_hash = records.last().map(|record| record.hash.as_str());
    if anchor.record_count != expected_count || expected_hash != Some(anchor.last_hash.as_str()) {
        return Err(KwpError::Internal(
            "KWP audit log does not match its integrity anchor".to_string(),
        ));
    }
    Ok(records)
}

fn read_kwp_audit_anchor(path: &Path) -> Result<KwpAuditAnchor, KwpError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        KwpError::Internal(format!(
            "could not inspect KWP audit anchor {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(KwpError::denied("audit.anchor"));
    }
    if metadata.len() > KWP_MAX_MESSAGE_BYTES as u64 {
        return Err(KwpError::quota("audit.anchor.bytes"));
    }
    let body = fs::read(path).map_err(|error| {
        KwpError::Internal(format!(
            "could not read KWP audit anchor {}: {error}",
            path.display()
        ))
    })?;
    serde_json::from_slice(&body).map_err(|error| {
        KwpError::Internal(format!(
            "could not parse KWP audit anchor {}: {error}",
            path.display()
        ))
    })
}

fn write_kwp_audit_anchor(
    path: &Path,
    record_count: usize,
    last_hash: String,
) -> Result<(), KwpError> {
    ensure_jsonl_append_target(path, "audit.anchor")?;
    let bytes = serde_json::to_vec(&KwpAuditAnchor {
        record_count: record_count as u64,
        last_hash,
    })
    .map_err(|error| KwpError::Internal(format!("could not serialize audit anchor: {error}")))?;
    crate::fs_atomic::write_atomic_bytes(path, &bytes).map_err(|error| {
        KwpError::Internal(format!(
            "could not write KWP audit anchor {}: {error}",
            path.display()
        ))
    })
}

fn path_exists_without_follow(path: &Path) -> Result<bool, KwpError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(KwpError::denied("audit.symlink")),
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err(KwpError::Internal(format!(
            "KWP audit path is not a file: {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(KwpError::Internal(format!(
            "could not inspect KWP audit path {}: {error}",
            path.display()
        ))),
    }
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

fn append_kwp_audit_log_record(
    path: &Path,
    body: KwpAuditLogBody,
) -> Result<KwpAuditLogRecord, KwpError> {
    let hash = kwp_audit_record_hash(&body)?;
    let record = body.into_record(hash);
    ensure_kwp_audit_parent(path)?;
    ensure_jsonl_append_target(path, "audit.log")?;
    let line = serialize_kwp_audit_record(&record)?;
    append_and_sync_kwp_audit_line(path, &line)?;
    Ok(record)
}

fn ensure_kwp_audit_parent(path: &Path) -> Result<(), KwpError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            KwpError::Internal(format!(
                "could not create KWP audit dir {}: {error}",
                parent.display()
            ))
        })?;
    }
    Ok(())
}

fn serialize_kwp_audit_record(record: &KwpAuditLogRecord) -> Result<String, KwpError> {
    serde_json::to_string(record).map_err(|error| {
        KwpError::Internal(format!("could not serialize KWP audit record: {error}"))
    })
}

fn append_and_sync_kwp_audit_line(path: &Path, line: &str) -> Result<(), KwpError> {
    let mut file = open_jsonl_append(path).map_err(|error| {
        KwpError::Internal(format!(
            "could not open KWP audit log {}: {error}",
            path.display()
        ))
    })?;
    writeln!(file, "{line}").map_err(|error| {
        KwpError::Internal(format!(
            "could not append KWP audit log {}: {error}",
            path.display()
        ))
    })?;
    file.sync_all().map_err(|error| {
        KwpError::Internal(format!(
            "could not sync KWP audit log {}: {error}",
            path.display()
        ))
    })?;
    crate::fs_atomic::sync_parent_dir(path).map_err(|error| {
        KwpError::Internal(format!(
            "could not sync KWP audit dir {}: {error}",
            path.display()
        ))
    })
}

fn append_kwp_bus_event(path: &Path, event: KwpBusEvent) -> Result<(), KwpError> {
    ensure_jsonl_append_target(path, "bus.log")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            KwpError::Internal(format!(
                "could not create KWP bus dir {}: {error}",
                parent.display()
            ))
        })?;
    }
    let mut file = open_jsonl_append(path).map_err(|error| {
        KwpError::Internal(format!(
            "could not open KWP bus log {}: {error}",
            path.display()
        ))
    })?;
    let line = serde_json::to_string(&event).map_err(|error| {
        KwpError::Internal(format!("could not serialize KWP bus event: {error}"))
    })?;
    writeln!(file, "{line}").map_err(|error| {
        KwpError::Internal(format!(
            "could not append KWP bus log {}: {error}",
            path.display()
        ))
    })?;
    file.sync_all().map_err(|error| {
        KwpError::Internal(format!(
            "could not sync KWP bus log {}: {error}",
            path.display()
        ))
    })?;
    crate::fs_atomic::sync_parent_dir(path).map_err(|error| {
        KwpError::Internal(format!(
            "could not sync KWP bus dir {}: {error}",
            path.display()
        ))
    })
}

#[cfg(unix)]
fn open_jsonl_append(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_jsonl_append(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new().create(true).append(true).open(path)
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
        Err(error) => Err(KwpError::Internal(format!(
            "could not inspect {}: {error}",
            path.display()
        ))),
    }
}

fn kwp_audit_record_hash(body: &KwpAuditLogBody) -> Result<String, KwpError> {
    let bytes = serde_json::to_vec(body)
        .map_err(|error| KwpError::Internal(format!("could not hash KWP audit record: {error}")))?;
    Ok(sha256_digest(&bytes).0)
}

fn ensure_quota_remaining(remaining: u64, resource: &str) -> Result<(), KwpError> {
    if remaining == 0 {
        return Err(KwpError::quota(resource));
    }
    Ok(())
}

fn validate_mcp_request(
    grant: &McpGrant,
    request: &McpCallRequest,
    catalog: &McpCatalog,
) -> Result<(), KwpError> {
    ensure_supported_mcp_grant(grant)?;
    ensure_mcp_grant_allows_tool(grant, &request.tool)?;
    ensure_mcp_catalog_allows_tool(catalog, &request.alias, &request.tool)
}

fn ensure_mcp_grant_allows_tool(grant: &McpGrant, tool: &str) -> Result<(), KwpError> {
    if !grant.allows_tool(tool) {
        return Err(KwpError::denied("mcp.tool"));
    }
    Ok(())
}

fn ensure_mcp_catalog_allows_tool(
    catalog: &McpCatalog,
    alias: &str,
    tool: &str,
) -> Result<(), KwpError> {
    let entry = catalog
        .get(alias)
        .ok_or_else(|| KwpError::denied("mcp.mount"))?;
    if !entry.tools.contains_key(tool) {
        return Err(KwpError::denied("mcp.catalog.tool"));
    }
    Ok(())
}

fn validate_authorized_fuzz_request(
    grant_set: &Grant,
    grant: &FuzzGrant,
    request: &FuzzRunRequest,
) -> Result<(), KwpError> {
    ensure_fuzz_engine_allowed(grant, request.engine)?;
    validate_fuzz_execution_request(request)?;
    ensure_fuzz_artifact_grant(grant_set)?;
    validate_fuzz_request_paths(request)
}

fn ensure_fuzz_engine_allowed(grant: &FuzzGrant, engine: FuzzEngine) -> Result<(), KwpError> {
    if !grant.allows_engine(engine) {
        return Err(KwpError::denied("fuzz.engine"));
    }
    Ok(())
}

fn ensure_fuzz_artifact_grant(grant: &Grant) -> Result<(), KwpError> {
    if grant
        .artifacts
        .as_ref()
        .filter(|grant| grant.write)
        .is_none()
    {
        return Err(KwpError::denied("artifacts.write"));
    }
    Ok(())
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
    pub async fn fs_read(
        &self,
        inv: &InvocationAuthority,
        scope: FsScope,
        path: &str,
    ) -> Result<FsReadResult, KwpError> {
        self.ensure_live(inv, "fs.read").await?;
        let grant = self
            .require(
                inv,
                "fs.read",
                inv.grant()
                    .fs_scope(scope)
                    .ok_or_else(|| KwpError::denied("fs")),
            )
            .await?;
        self.require(inv, "fs.read", validate_broker_fs_path(scope, path))
            .await?;
        let remaining = inv.remaining_fs_bytes(grant).await;
        self.require(
            inv,
            "fs.read",
            ensure_quota_remaining(remaining, "fs.bytes"),
        )
        .await?;
        let result = self
            .meter_fs_read(
                inv,
                grant,
                path,
                self.fs.read(scope, path, 0, Some(remaining)).await,
            )
            .await;
        self.record(inv, "fs.read", &result).await;
        result
    }

    pub async fn fs_write(
        &self,
        inv: &InvocationAuthority,
        scope: FsScope,
        path: &str,
        data: Vec<u8>,
    ) -> Result<u64, KwpError> {
        self.ensure_live(inv, "fs.write").await?;
        let Some(grant) = inv
            .grant()
            .fs_scope(scope)
            .filter(|grant| grant.mode == FsMode::Rw && scope != FsScope::Input)
        else {
            return self
                .deny(inv, "fs.write", KwpError::denied("fs.write"))
                .await;
        };
        if let Err(error) = validate_broker_fs_path(scope, path) {
            return self.deny(inv, "fs.write", error).await;
        }
        if let Err(error) = inv.reserve_fs_access(grant, path, data.len() as u64).await {
            return self.deny(inv, "fs.write", error).await;
        }
        let result = self.fs.write(scope, path, data, false).await;
        self.record(inv, "fs.write", &result).await;
        result
    }

    pub async fn net_fetch(
        &self,
        inv: &InvocationAuthority,
        request: NetFetchRequest,
    ) -> Result<NetFetchResult, KwpError> {
        self.ensure_live(inv, "net.fetch").await?;
        let Some(grant) = inv.grant().net.as_ref() else {
            return self.deny(inv, "net.fetch", KwpError::denied("net")).await;
        };
        let request = match validate_net_fetch_request(grant, request) {
            Ok(checked) => checked.request,
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

    pub async fn runtime_query(
        &self,
        inv: &InvocationAuthority,
        request: RuntimeQueryRequest,
    ) -> Result<RuntimeQueryResult, KwpError> {
        self.ensure_live(inv, "runtime.query").await?;
        let Some(grant) = inv.grant().runtime.as_ref() else {
            return self
                .deny(inv, "runtime.query", KwpError::denied("runtime"))
                .await;
        };
        if inv.computed_cost_usd().await >= grant.max_cost_usd_per_invocation
            || kwp_run_cost(inv.run_id())? >= grant.max_cost_usd_per_run
        {
            return self
                .deny(inv, "runtime.query", KwpError::RuntimeBudget)
                .await;
        }
        let mut result = self.runtime.query(with_provenance(inv, request)).await;
        if let Some(cost_usd) = result.as_ref().ok().map(|result| result.cost_usd) {
            let run_cost = record_kwp_run_cost(inv.run_id(), cost_usd)?;
            inv.add_runtime_cost(cost_usd).await;
            if inv.computed_cost_usd().await > grant.max_cost_usd_per_invocation
                || run_cost > grant.max_cost_usd_per_run
            {
                result = Err(KwpError::RuntimeBudget);
            }
        }
        self.record(inv, "runtime.query", &result).await;
        result
    }

    pub async fn bus_publish(
        &self,
        inv: &InvocationAuthority,
        topic: String,
        payload: Value,
    ) -> Result<(), KwpError> {
        self.ensure_live(inv, "bus.publish").await?;
        if !inv
            .grant()
            .bus
            .produce
            .iter()
            .any(|pattern| pattern.matches(&topic))
        {
            return self
                .deny(inv, "bus.publish", KwpError::denied("bus.produce"))
                .await;
        }
        let result = self.bus.publish(origin(inv), topic, payload).await;
        self.record(inv, "bus.publish", &result).await;
        result
    }

    pub async fn findings_create(
        &self,
        inv: &InvocationAuthority,
        findings: Vec<Value>,
    ) -> Result<FindingsCreateResult, KwpError> {
        self.ensure_live(inv, "findings.create").await?;
        let Some(grant) = inv.grant().findings.as_ref().filter(|grant| grant.create) else {
            return self
                .deny(inv, "findings.create", KwpError::denied("findings.create"))
                .await;
        };
        if let Some(max) = grant.max_per_invocation {
            if findings.len() > max as usize {
                return self
                    .deny(inv, "findings.create", KwpError::quota("findings.count"))
                    .await;
            }
        }
        let result = self.findings.create(origin(inv), findings).await;
        self.record(inv, "findings.create", &result).await;
        result
    }

    pub async fn artifacts_record(
        &self,
        inv: &InvocationAuthority,
        artifacts: Vec<ArtifactRef>,
    ) -> Result<Vec<ArtifactRef>, KwpError> {
        self.ensure_live(inv, "artifacts.record").await?;
        if inv
            .grant()
            .artifacts
            .as_ref()
            .filter(|grant| grant.write)
            .is_none()
        {
            return self
                .deny(inv, "artifacts.record", KwpError::denied("artifacts.write"))
                .await;
        }
        if let Err(error) = validate_artifact_refs(&artifacts) {
            return self.deny(inv, "artifacts.record", error).await;
        }
        let result = self.artifacts.record(origin(inv), artifacts).await;
        self.record(inv, "artifacts.record", &result).await;
        result
    }

    pub async fn mcp_call(
        &self,
        inv: &InvocationAuthority,
        mut request: McpCallRequest,
    ) -> Result<McpCallResult, KwpError> {
        self.ensure_live(inv, "mcp.call").await?;
        let grant = self.authorize_mcp_call(inv, &mut request).await?;
        let result = self
            .mcp
            .call(mcp_session(inv, &request.alias), request)
            .await
            .and_then(validate_mcp_result);
        let result = self.meter_mcp_result(inv, grant, result).await;
        self.record(inv, "mcp.call", &result).await;
        result
    }

    pub async fn fuzz_run(
        &self,
        inv: &InvocationAuthority,
        request: FuzzRunRequest,
    ) -> Result<FuzzRunResult, KwpError> {
        self.ensure_live(inv, "fuzz.run").await?;
        self.authorize_fuzz_run(inv, &request).await?;
        let limits = request.limits.clone();
        let result = self
            .fuzz
            .run(origin(inv), request)
            .await
            .and_then(|result| validate_fuzz_result(result, &limits));
        self.record(inv, "fuzz.run", &result).await;
        result
    }

    async fn authorize_mcp_call<'a>(
        &self,
        inv: &'a InvocationAuthority,
        request: &mut McpCallRequest,
    ) -> Result<&'a McpGrant, KwpError> {
        self.require(
            inv,
            "mcp.call",
            inv.ensure_invocation_id(&request.invocation_id),
        )
        .await?;
        let grant = self
            .require(
                inv,
                "mcp.call",
                inv.grant()
                    .mcp_grant(&request.alias)
                    .ok_or_else(|| KwpError::denied("mcp")),
            )
            .await?;
        self.require(
            inv,
            "mcp.call",
            validate_mcp_request(grant, request, &self.mcp_catalog),
        )
        .await?;
        apply_mcp_grant_limits(grant, &mut request.limits);
        self.require(
            inv,
            "mcp.call",
            inv.reserve_mcp_call(grant, &request.limits).await,
        )
        .await?;
        Ok(grant)
    }

    async fn authorize_fuzz_run(
        &self,
        inv: &InvocationAuthority,
        request: &FuzzRunRequest,
    ) -> Result<(), KwpError> {
        self.require(
            inv,
            "fuzz.run",
            inv.ensure_invocation_id(&request.invocation_id),
        )
        .await?;
        let grant = self
            .require(
                inv,
                "fuzz.run",
                inv.grant()
                    .fuzz
                    .as_ref()
                    .ok_or_else(|| KwpError::denied("fuzz")),
            )
            .await?;
        self.require(
            inv,
            "fuzz.run",
            validate_authorized_fuzz_request(inv.grant(), grant, request),
        )
        .await?;
        self.require(inv, "fuzz.run", inv.reserve_fuzz_job(grant, request).await)
            .await
    }

    async fn meter_fs_read(
        &self,
        inv: &InvocationAuthority,
        grant: &FsScopeGrant,
        path: &str,
        result: Result<FsReadResult, KwpError>,
    ) -> Result<FsReadResult, KwpError> {
        let read = result?;
        inv.reserve_fs_access(grant, path, read.data.len() as u64)
            .await?;
        Ok(read)
    }

    async fn meter_mcp_result(
        &self,
        inv: &InvocationAuthority,
        grant: &McpGrant,
        result: Result<McpCallResult, KwpError>,
    ) -> Result<McpCallResult, KwpError> {
        let result = result?;
        inv.reserve_mcp_result(grant, &result).await?;
        Ok(result)
    }

    async fn ensure_live(&self, inv: &InvocationAuthority, event: &str) -> Result<(), KwpError> {
        let result = inv.ensure_active().and_then(|_| inv.ensure_epoch_current());
        if result.is_err() {
            self.record(inv, event, &result).await;
        }
        result
    }

    async fn deny<T>(
        &self,
        inv: &InvocationAuthority,
        event: &str,
        error: KwpError,
    ) -> Result<T, KwpError> {
        let result = Err(error);
        self.record(inv, event, &result).await;
        result
    }

    async fn require<T>(
        &self,
        inv: &InvocationAuthority,
        event: &str,
        result: Result<T, KwpError>,
    ) -> Result<T, KwpError> {
        match result {
            Ok(value) => Ok(value),
            Err(error) => self.deny(inv, event, error).await,
        }
    }

    async fn record<T>(
        &self,
        inv: &InvocationAuthority,
        event: &str,
        result: &Result<T, KwpError>,
    ) {
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

fn validate_fuzz_result(
    result: FuzzRunResult,
    limits: &FuzzLimits,
) -> Result<FuzzRunResult, KwpError> {
    validate_artifact_refs(&result.artifacts)?;
    if limits
        .max_crashes
        .is_some_and(|max| result.crashes.len() > max as usize)
    {
        return Err(KwpError::quota("fuzz.crashes"));
    }
    Ok(result)
}

fn with_provenance(
    inv: &InvocationAuthority,
    mut request: RuntimeQueryRequest,
) -> RuntimeQueryRequest {
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
    endpoint: NetEndpoint,
    pinned_addr: SocketAddr,
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

fn validate_net_fetch_request(
    grant: &NetGrant,
    request: NetFetchRequest,
) -> Result<ValidatedNetFetch, KwpError> {
    let endpoint = parse_https_endpoint(&request.url)?;
    if is_forbidden_net_host(&endpoint.host) {
        return Err(KwpError::denied("net.ssr.host"));
    }
    if !grant
        .allow
        .iter()
        .any(|pattern| pattern.matches(&endpoint.host, endpoint.port))
    {
        return Err(KwpError::denied("net.host"));
    }
    if let Some(credential_name) = request.credential_name.as_deref() {
        validate_named_credential(grant, credential_name)?;
    }
    validate_net_request_size(grant, &request)?;
    let pinned_addr = resolve_public_endpoint(&endpoint)?;
    Ok(ValidatedNetFetch {
        request: with_host_controlled_headers(strip_untrusted_headers(request))?,
        endpoint,
        pinned_addr,
        response_byte_limit: grant.max_bytes_per_invocation,
    })
}

#[derive(Debug)]
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
    let port = url
        .port_or_known_default()
        .ok_or_else(|| KwpError::denied("net.port"))?;
    Ok(NetEndpoint { host, port })
}

fn normalized_net_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn validate_named_credential(grant: &NetGrant, credential_name: &str) -> Result<(), KwpError> {
    if grant
        .credentials
        .iter()
        .any(|allowed| allowed == credential_name)
    {
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

fn resolve_public_endpoint(endpoint: &NetEndpoint) -> Result<SocketAddr, KwpError> {
    if let Ok(ip) = endpoint.host.parse::<IpAddr>() {
        ensure_public_ip(ip)?;
        return Ok(SocketAddr::new(ip, endpoint.port));
    }
    let addrs = (endpoint.host.as_str(), endpoint.port)
        .to_socket_addrs()
        .map_err(|_| KwpError::denied("net.dns"))?
        .collect::<Vec<_>>();
    validated_public_socket(addrs)
}

fn validated_public_socket(addrs: Vec<SocketAddr>) -> Result<SocketAddr, KwpError> {
    let pinned = *addrs.first().ok_or_else(|| KwpError::denied("net.dns"))?;
    for addr in addrs {
        ensure_public_socket(addr)?;
    }
    Ok(pinned)
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
        lower != "authorization"
            && lower != "cookie"
            && !lower.starts_with("proxy-")
            && !lower.starts_with("x-forwarded-")
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
    total_bytes: &mut u64,
    request: NetResponseArtifactRequest,
    headers: &BTreeMap<String, String>,
    body: &[u8],
) -> Result<ArtifactRef, KwpError> {
    validate_relative_path(&request.path).map_err(|_| KwpError::denied("artifact.path"))?;
    ensure_artifact_byte_budget(grant, *total_bytes, body.len() as u64)?;
    let media_type = request
        .media_type
        .filter(|value| !value.trim().is_empty())
        .or_else(|| response_content_type(headers))
        .unwrap_or_else(|| "application/octet-stream".to_string());
    let path = resolve_write_path(root, &request.path)?;
    write_fs_file_no_follow(&path, body, false)?;
    let artifact = ArtifactRef {
        path: request.path,
        media_type,
        sha256: None,
    };
    verify_artifact_ref(root, grant, total_bytes, artifact)
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
    Ok(std::env::var(env_name)
        .ok()
        .filter(|value| !value.trim().is_empty()))
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
        Self {
            code: error.code(),
            message: error.to_string(),
        }
    }
}

pub fn encode_rpc_line(message: &RpcMessage) -> Result<Vec<u8>, KwpError> {
    validate_rpc_version(message)?;
    let mut bytes =
        serde_json::to_vec(message).map_err(|error| KwpError::Internal(error.to_string()))?;
    enforce_message_size(bytes.len().saturating_add(1), "rpc.message_bytes")?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn decode_rpc_line(bytes: &[u8]) -> Result<RpcMessage, KwpError> {
    enforce_message_size(bytes.len(), "rpc.message_bytes")?;
    let message =
        serde_json::from_slice(bytes).map_err(|error| KwpError::BadRequest(error.to_string()))?;
    validate_rpc_version(&message)?;
    Ok(message)
}

fn enforce_message_size(bytes: usize, resource: &str) -> Result<(), KwpError> {
    if bytes > KWP_MAX_MESSAGE_BYTES {
        Err(KwpError::quota(resource))
    } else {
        Ok(())
    }
}

fn validate_rpc_version(message: &RpcMessage) -> Result<(), KwpError> {
    if message.jsonrpc_version() == "2.0" {
        Ok(())
    } else {
        Err(KwpError::BadRequest(
            "jsonrpc version must be 2.0".to_string(),
        ))
    }
}

#[async_trait]
pub trait WorkerTransport: Send + Sync {
    async fn send(&self, message: RpcMessage) -> Result<(), KwpError>;
    async fn recv(&self) -> Result<Option<RpcMessage>, KwpError>;
}

#[async_trait]
pub trait WorkerExecutor: Send + Sync {
    async fn spawn(
        &self,
        module: VerifiedModule,
        mode: WorkerMode,
    ) -> Result<SpawnedWorker, KwpError>;
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
    let context = run.context;
    ensure_tool_execution_active(context)?;
    let (invocation_id, run_id) = worker_invocation_ids(context);
    let mut child = spawn_node_worker(&mut run.command, run.module)?;
    let mut stdin = take_worker_stdin(&mut child)?;
    let stdout = take_worker_stdout(&mut child)?;
    tag_worker_stderr(&mut child, run.module, run.tool_name);
    let process_group_id = kwp_child_process_group_id(&child);
    let cancellation = crate::scan::ScanCancellation::default();
    let child = cancellation
        .register_child(child, process_group_id)
        .map_err(|error| cancellation_error(context, error))?;
    let mut session = new_worker_host_session(
        run.module,
        run.tool_name,
        context,
        run.runtime,
        invocation_id,
        run_id,
    );
    let receiver = spawn_worker_stdout_reader(stdout);
    let result = session
        .record_invocation_start()
        .and_then(|_| initialize_then_call_worker(&receiver, &mut stdin, run, &mut session));
    let audit_result = finalize_worker_invocation(&mut session, &result, context);
    let _ = child.kill_and_wait();
    audit_result?;
    result
}

fn worker_invocation_ids(
    context: &crate::modules::ToolExecutionContext<'_>,
) -> (InvocationId, RunId) {
    let invocation_id = InvocationId(format!("kwp-{}", uuid::Uuid::new_v4()));
    let run_id = context
        .run_id()
        .unwrap_or_else(|| format!("run-{}", uuid::Uuid::new_v4()));
    (invocation_id, RunId(run_id))
}

fn new_worker_host_session<'a>(
    module: &'a VerifiedModule,
    tool_name: &'a str,
    context: &'a crate::modules::ToolExecutionContext<'a>,
    runtime: Option<&'a dyn crate::runtime::AgentRuntime>,
    invocation_id: InvocationId,
    run_id: RunId,
) -> WorkerHostSession<'a> {
    WorkerHostSession {
        module,
        tool_name,
        invocation_id,
        run_id,
        context,
        runtime,
        runtime_cost_usd: 0.0,
        fs_access: FsAccessMeter::default(),
        net_access: NetAccessMeter::default(),
        mcp_calls: BTreeMap::new(),
        mcp_bytes: BTreeMap::new(),
        mcp_host: HostMcpBroker::from_config(context.config, context.workspace),
        fuzz_jobs: 0,
        fuzz_host: HostFuzzExecutor::from_config(context.config, context.workspace),
        recorded_artifacts: Vec::new(),
        artifact_bytes: 0,
        created_findings: 0,
        deadline: worker_deadline(context.config),
        epoch: KWP_WORKER_EPOCH,
        initializing: true,
        cancel_recorded: false,
        settled: false,
    }
}

fn finalize_worker_invocation(
    session: &mut WorkerHostSession<'_>,
    result: &Result<Value, KwpError>,
    context: &crate::modules::ToolExecutionContext<'_>,
) -> Result<(), KwpError> {
    let cancel_result = invocation_cancel_reason(result, context)
        .map(|reason| session.record_invocation_cancel(reason))
        .unwrap_or(Ok(()));
    session.settled = true;
    cancel_result.and_then(|_| session.record_invocation_end(result))
}

fn ensure_tool_execution_active(
    _context: &crate::modules::ToolExecutionContext<'_>,
) -> Result<(), KwpError> {
    Ok(())
}

fn tool_execution_cancelled(_context: &crate::modules::ToolExecutionContext<'_>) -> bool {
    false
}

fn cancellation_error(
    context: &crate::modules::ToolExecutionContext<'_>,
    error: anyhow::Error,
) -> KwpError {
    if tool_execution_cancelled(context) {
        KwpError::NoActiveInvocation
    } else {
        KwpError::Internal(format!("could not supervise KWP worker: {error}"))
    }
}

fn invocation_cancel_reason<'a>(
    result: &Result<Value, KwpError>,
    context: &'a crate::modules::ToolExecutionContext<'_>,
) -> Option<&'a str> {
    if matches!(result, Err(KwpError::Deadline)) {
        return Some("deadline");
    }
    tool_execution_cancelled(context).then_some("operator")
}

fn spawn_node_worker(command: &mut Command, module: &VerifiedModule) -> Result<Child, KwpError> {
    configure_kwp_process_group(command);
    command
        .current_dir(&module.module_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| KwpError::Internal(format!("could not start KWP worker: {error}")))
}

fn kwp_child_process_group_id(child: &Child) -> Option<u32> {
    #[cfg(unix)]
    {
        Some(child.id())
    }
    #[cfg(not(unix))]
    {
        let _ = child;
        None
    }
}

fn configure_kwp_process_group(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
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
    {
        let _ = command;
    }
}

fn kill_kwp_child_process(child: &mut Child) {
    #[cfg(unix)]
    unsafe {
        libc::killpg(child.id() as libc::pid_t, libc::SIGKILL);
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
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
    session.initializing = false;

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
        "cwd": ".",
        "config": {
            "model": ctx.config.model,
        },
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

fn worker_runtime_cwd(
    module: &VerifiedModule,
    ctx: &crate::modules::ToolExecutionContext<'_>,
) -> PathBuf {
    ctx.workspace
        .map(|workspace| workspace.root().to_path_buf())
        .unwrap_or_else(|| module.module_root.clone())
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
        let message =
            next_active_worker_message(receiver, stdin, request_id, session, attach_metrics)?;
        match apply_worker_message(
            message,
            receiver,
            stdin,
            request_id,
            session,
            attach_metrics,
        )? {
            WorkerMessageOutcome::Continue => {}
            WorkerMessageOutcome::Complete(result) => return Ok(result),
        }
    }
}

enum WorkerMessageOutcome {
    Continue,
    Complete(Value),
}

fn next_active_worker_message(
    receiver: &mpsc::Receiver<Result<Option<RpcMessage>, KwpError>>,
    stdin: &mut impl Write,
    request_id: &RpcId,
    session: &mut WorkerHostSession<'_>,
    attach_metrics: bool,
) -> Result<RpcMessage, KwpError> {
    let message = read_next_worker_message(receiver, session.deadline, session.tool_name, None)
        .map_err(|error| {
            settle_worker_read_error(error, receiver, stdin, request_id, session, attach_metrics)
        })?;
    ensure_worker_invocation_active(receiver, stdin, request_id, session, attach_metrics)?;
    Ok(message)
}

fn settle_worker_read_error(
    error: KwpError,
    receiver: &mpsc::Receiver<Result<Option<RpcMessage>, KwpError>>,
    stdin: &mut impl Write,
    request_id: &RpcId,
    session: &mut WorkerHostSession<'_>,
    attach_metrics: bool,
) -> KwpError {
    match error {
        KwpError::Deadline => {
            settle_worker_timeout(receiver, stdin, request_id, session, attach_metrics)
        }
        KwpError::NoActiveInvocation => {
            settle_worker_inactive(receiver, stdin, request_id, session, attach_metrics)
        }
        error => error,
    }
}

fn settle_worker_timeout(
    receiver: &mpsc::Receiver<Result<Option<RpcMessage>, KwpError>>,
    stdin: &mut impl Write,
    request_id: &RpcId,
    session: &mut WorkerHostSession<'_>,
    attach_metrics: bool,
) -> KwpError {
    if attach_metrics {
        cancel_worker_invocation(stdin, receiver, request_id, session, "deadline");
    }
    KwpError::Deadline
}

fn settle_worker_inactive(
    receiver: &mpsc::Receiver<Result<Option<RpcMessage>, KwpError>>,
    stdin: &mut impl Write,
    request_id: &RpcId,
    session: &mut WorkerHostSession<'_>,
    attach_metrics: bool,
) -> KwpError {
    if attach_metrics && tool_execution_cancelled(session.context) {
        cancel_worker_invocation(stdin, receiver, request_id, session, "operator");
    }
    KwpError::NoActiveInvocation
}

fn ensure_worker_invocation_active(
    receiver: &mpsc::Receiver<Result<Option<RpcMessage>, KwpError>>,
    stdin: &mut impl Write,
    request_id: &RpcId,
    session: &mut WorkerHostSession<'_>,
    attach_metrics: bool,
) -> Result<(), KwpError> {
    if !tool_execution_cancelled(session.context) {
        return Ok(());
    }
    if attach_metrics {
        cancel_worker_invocation(stdin, receiver, request_id, session, "operator");
    }
    Err(KwpError::NoActiveInvocation)
}

fn apply_worker_message(
    message: RpcMessage,
    receiver: &mpsc::Receiver<Result<Option<RpcMessage>, KwpError>>,
    stdin: &mut impl Write,
    request_id: &RpcId,
    session: &mut WorkerHostSession<'_>,
    attach_metrics: bool,
) -> Result<WorkerMessageOutcome, KwpError> {
    match message {
        RpcMessage::Response { id, result, .. } => handle_worker_success(
            id,
            result,
            receiver,
            stdin,
            request_id,
            session,
            attach_metrics,
        ),
        RpcMessage::ErrorResponse { id, error, .. } => handle_worker_error(
            id,
            error,
            receiver,
            stdin,
            request_id,
            session,
            attach_metrics,
        ),
        RpcMessage::Request {
            id, method, params, ..
        } => {
            let response = session.handle_worker_request(method, params);
            write_rpc_message(stdin, &response_message(id, response))?;
            Ok(WorkerMessageOutcome::Continue)
        }
        RpcMessage::Notification { .. } => Ok(WorkerMessageOutcome::Continue),
    }
}

fn handle_worker_success(
    id: RpcId,
    result: Value,
    receiver: &mpsc::Receiver<Result<Option<RpcMessage>, KwpError>>,
    stdin: &mut impl Write,
    request_id: &RpcId,
    session: &mut WorkerHostSession<'_>,
    attach_metrics: bool,
) -> Result<WorkerMessageOutcome, KwpError> {
    if &id != request_id {
        return Ok(WorkerMessageOutcome::Continue);
    }
    ensure_worker_response_timely(receiver, stdin, request_id, session, attach_metrics)?;
    let result = if attach_metrics {
        session.attach_host_metrics(result)
    } else {
        result
    };
    Ok(WorkerMessageOutcome::Complete(result))
}

fn handle_worker_error(
    id: RpcId,
    error: RpcError,
    receiver: &mpsc::Receiver<Result<Option<RpcMessage>, KwpError>>,
    stdin: &mut impl Write,
    request_id: &RpcId,
    session: &mut WorkerHostSession<'_>,
    attach_metrics: bool,
) -> Result<WorkerMessageOutcome, KwpError> {
    if &id != request_id {
        return Ok(WorkerMessageOutcome::Continue);
    }
    ensure_worker_response_timely(receiver, stdin, request_id, session, attach_metrics)?;
    Err(KwpError::Internal(format!(
        "worker error {}: {}",
        error.code, error.message
    )))
}

fn ensure_worker_response_timely(
    receiver: &mpsc::Receiver<Result<Option<RpcMessage>, KwpError>>,
    stdin: &mut impl Write,
    request_id: &RpcId,
    session: &mut WorkerHostSession<'_>,
    attach_metrics: bool,
) -> Result<(), KwpError> {
    session.ensure_before_deadline().map_err(|error| {
        settle_worker_read_error(error, receiver, stdin, request_id, session, attach_metrics)
    })
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
            Ok(Ok(Some(RpcMessage::Request {
                id, method, params, ..
            }))) => {
                let response = session.handle_worker_request(method, params);
                let _ = write_rpc_message(stdin, &response_message(id, response));
            }
            Ok(Ok(Some(
                RpcMessage::Response { id, .. } | RpcMessage::ErrorResponse { id, .. },
            ))) if &id == request_id => {
                // The invocation is already host-settled. Drop the worker's
                // late result and keep the broker open briefly so any cleanup
                // calls are denied and audited by the host.
            }
            Ok(Ok(Some(
                RpcMessage::Response { .. }
                | RpcMessage::ErrorResponse { .. }
                | RpcMessage::Notification { .. },
            ))) => {}
            Ok(Ok(None))
            | Ok(Err(_))
            | Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}

fn validate_worker_initialize(
    initialize: &Value,
    module: &VerifiedModule,
    tool_name: &str,
) -> Result<(), KwpError> {
    let version = worker_protocol_version(initialize)?;
    ensure_worker_protocol_version(version)?;
    let descriptor = worker_initialize_descriptor(initialize)?;
    ensure_worker_module_id(&descriptor, module)?;
    ensure_worker_tool_advertised(&descriptor, tool_name)?;
    let descriptor_hash = worker_initialize_descriptor_hash(&descriptor)?;
    ensure_worker_descriptor_hash(&descriptor_hash, module)
}

fn worker_protocol_version(initialize: &Value) -> Result<&str, KwpError> {
    initialize
        .get("protocolVersion")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            KwpError::BadRequest("worker initialize omitted protocolVersion".to_string())
        })
}

fn ensure_worker_protocol_version(version: &str) -> Result<(), KwpError> {
    if version != KWP_VERSION {
        return Err(KwpError::BadRequest(format!(
            "worker protocolVersion {version:?} does not match host {KWP_VERSION:?}"
        )));
    }
    Ok(())
}

fn ensure_worker_module_id(
    descriptor: &WorkerInitializeDescriptor,
    module: &VerifiedModule,
) -> Result<(), KwpError> {
    if descriptor.module.id != module.module_id.0 {
        return Err(KwpError::BadRequest(format!(
            "worker module id {module_id:?} does not match approved module {:?}",
            module.module_id.0,
            module_id = descriptor.module.id
        )));
    }
    Ok(())
}

fn ensure_worker_tool_advertised(
    descriptor: &WorkerInitializeDescriptor,
    tool_name: &str,
) -> Result<(), KwpError> {
    if !descriptor.tools.iter().any(|tool| tool.name == tool_name) {
        return Err(KwpError::BadRequest(format!(
            "worker initialize did not advertise tool {tool_name:?}"
        )));
    }
    Ok(())
}

fn worker_initialize_descriptor_hash(
    descriptor: &WorkerInitializeDescriptor,
) -> Result<String, KwpError> {
    let descriptor_value =
        serde_json::to_value(&descriptor).map_err(|error| KwpError::Internal(error.to_string()))?;
    descriptor_hash_from_value(&descriptor_value)
        .map_err(|error| KwpError::Internal(error.to_string()))
}

fn ensure_worker_descriptor_hash(
    descriptor_hash: &str,
    module: &VerifiedModule,
) -> Result<(), KwpError> {
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
    #[serde(default)]
    hidden: bool,
    tools: Vec<crate::modules::ToolDescriptor>,
}

fn worker_initialize_descriptor(
    initialize: &Value,
) -> Result<WorkerInitializeDescriptor, KwpError> {
    serde_json::from_value(serde_json::json!({
        "module": initialize.get("module").cloned().unwrap_or(Value::Null),
        "hidden": initialize.get("hidden").cloned().unwrap_or(Value::Bool(false)),
        "tools": initialize.get("tools").cloned().unwrap_or(Value::Null),
    }))
    .map_err(|error| {
        KwpError::BadRequest(format!("worker initialize descriptor is invalid: {error}"))
    })
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
    loop {
        match read_bounded_line(&mut reader, "KWP worker stdout", "rpc.message_bytes") {
            Ok(None) => {
                let _ = sender.send(Ok(None));
                return;
            }
            Ok(Some(line)) => {
                if sender.send(decode_rpc_line(&line).map(Some)).is_err() {
                    return;
                }
            }
            Err(error) => {
                let _ = sender.send(Err(error));
                return;
            }
        }
    }
}

fn read_bounded_line(
    reader: &mut impl BufRead,
    label: &str,
    resource: &str,
) -> Result<Option<Vec<u8>>, KwpError> {
    let mut line = Vec::new();
    let read = reader
        .take((KWP_MAX_MESSAGE_BYTES + 1) as u64)
        .read_until(b'\n', &mut line)
        .map_err(|error| KwpError::Internal(format!("could not read {label}: {error}")))?;
    if read == 0 {
        return Ok(None);
    }
    enforce_message_size(line.len(), resource)?;
    Ok(Some(line))
}

fn read_next_worker_message(
    receiver: &mpsc::Receiver<Result<Option<RpcMessage>, KwpError>>,
    deadline: Instant,
    tool_name: &str,
    cancellation: Option<&crate::scan::ScanCancellation>,
) -> Result<RpcMessage, KwpError> {
    loop {
        if cancellation.is_some_and(crate::scan::ScanCancellation::is_cancelled) {
            return Err(KwpError::NoActiveInvocation);
        }
        let remaining = remaining_worker_time(deadline)?;
        let timeout = remaining.min(KWP_CANCEL_POLL);
        match receiver.recv_timeout(timeout) {
            Ok(Ok(Some(message))) => return Ok(message),
            Ok(Ok(None)) => return worker_exit_error(cancellation, tool_name),
            Ok(Err(error)) => return Err(error),
            Err(mpsc::RecvTimeoutError::Timeout) if remaining > KWP_CANCEL_POLL => {}
            Err(mpsc::RecvTimeoutError::Timeout) => return Err(KwpError::Deadline),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return worker_exit_error(cancellation, tool_name)
            }
        }
    }
}

fn worker_exit_error(
    cancellation: Option<&crate::scan::ScanCancellation>,
    tool_name: &str,
) -> Result<RpcMessage, KwpError> {
    if cancellation.is_some_and(crate::scan::ScanCancellation::is_cancelled) {
        return Err(KwpError::NoActiveInvocation);
    }
    Err(KwpError::Internal(format!(
        "KWP worker exited before {tool_name} returned a result"
    )))
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

#[derive(Clone, Copy)]
enum WorkerRuntimeResponseShape {
    Agent,
    Kwp,
}

struct PreparedWorkerRuntimeRequest {
    query: crate::runtime::AgentQueryRequest,
    response_shape: WorkerRuntimeResponseShape,
}

static KWP_RUN_COSTS: OnceLock<StdMutex<BTreeMap<RunId, f64>>> = OnceLock::new();

fn kwp_run_cost(run_id: &RunId) -> Result<f64, KwpError> {
    let costs = KWP_RUN_COSTS
        .get_or_init(|| StdMutex::new(BTreeMap::new()))
        .lock()
        .map_err(|_| KwpError::Internal("KWP run-cost ledger was poisoned".to_string()))?;
    Ok(costs.get(run_id).copied().unwrap_or(0.0))
}

fn record_kwp_run_cost(run_id: &RunId, cost: f64) -> Result<f64, KwpError> {
    if !cost.is_finite() || cost < 0.0 {
        return Err(KwpError::Internal(
            "runtime returned an invalid cost".to_string(),
        ));
    }
    let mut costs = KWP_RUN_COSTS
        .get_or_init(|| StdMutex::new(BTreeMap::new()))
        .lock()
        .map_err(|_| KwpError::Internal("KWP run-cost ledger was poisoned".to_string()))?;
    let total = costs.entry(run_id.clone()).or_default();
    *total += cost;
    Ok(*total)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerAgentRuntimeRequest {
    prompt: String,
    #[serde(default, alias = "systemPrompt")]
    system_prompt: Option<String>,
    #[serde(default, alias = "structuredOutput")]
    structured_output: Option<crate::runtime::AgentStructuredOutput>,
    #[serde(default, alias = "thinkingLevel")]
    thinking_level: Option<String>,
    #[serde(default, alias = "maxOutputTokens")]
    max_output_tokens: Option<u32>,
    #[serde(default)]
    temperature: Option<f32>,
}

fn prepare_worker_runtime_request(
    params: &Value,
    grant: &RuntimeGrant,
    configured_model: Option<&str>,
    cwd: &Path,
) -> Result<PreparedWorkerRuntimeRequest, KwpError> {
    if let Some(request) = params.get("request") {
        return prepare_agent_runtime_request(request.clone(), grant, configured_model, cwd);
    }
    let request: RuntimeQueryRequest = serde_json::from_value(params.clone())
        .map_err(|error| KwpError::BadRequest(error.to_string()))?;
    prepare_kwp_runtime_request(request, grant, configured_model, cwd)
}

fn prepare_agent_runtime_request(
    value: Value,
    grant: &RuntimeGrant,
    configured_model: Option<&str>,
    cwd: &Path,
) -> Result<PreparedWorkerRuntimeRequest, KwpError> {
    let request: WorkerAgentRuntimeRequest =
        serde_json::from_value(value).map_err(|error| KwpError::BadRequest(error.to_string()))?;
    let model = resolve_worker_runtime_model(configured_model, grant)?;
    validate_runtime_output_tokens(request.max_output_tokens)?;
    validate_runtime_sampling(request.thinking_level.as_deref(), request.temperature)?;
    let mut query = crate::runtime::AgentQueryRequest::new(
        model,
        cwd,
        request.system_prompt.unwrap_or_default(),
        request.prompt,
    );
    query.structured_output = request.structured_output;
    query.thinking_level = request.thinking_level;
    query.max_output_tokens = request.max_output_tokens;
    query.temperature = request.temperature;
    Ok(PreparedWorkerRuntimeRequest {
        query,
        response_shape: WorkerRuntimeResponseShape::Agent,
    })
}

fn prepare_kwp_runtime_request(
    request: RuntimeQueryRequest,
    grant: &RuntimeGrant,
    configured_model: Option<&str>,
    cwd: &Path,
) -> Result<PreparedWorkerRuntimeRequest, KwpError> {
    let model = resolve_worker_runtime_model(configured_model, grant)?;
    ensure_model_preference_matches(request.model_preferences.as_ref(), &model)?;
    validate_runtime_output_tokens(Some(request.max_tokens))?;
    let mut query = crate::runtime::AgentQueryRequest::new(
        model,
        cwd,
        request.system_prompt.unwrap_or_default(),
        kwp_runtime_prompt(&request.messages)?,
    );
    query.max_output_tokens = Some(request.max_tokens);
    Ok(PreparedWorkerRuntimeRequest {
        query,
        response_shape: WorkerRuntimeResponseShape::Kwp,
    })
}

fn resolve_worker_runtime_model(
    configured_model: Option<&str>,
    grant: &RuntimeGrant,
) -> Result<String, KwpError> {
    let selected = configured_model
        .map(str::trim)
        .filter(|model| !model.is_empty())
        .ok_or_else(|| KwpError::denied("runtime.model"))?;
    if grant
        .models
        .as_ref()
        .is_some_and(|models| !models.iter().any(|model| model == selected))
    {
        return Err(KwpError::denied("runtime.model"));
    }
    Ok(selected.to_string())
}

fn validate_runtime_output_tokens(tokens: Option<u32>) -> Result<(), KwpError> {
    if tokens.is_some_and(|tokens| tokens == 0 || tokens > KWP_MAX_RUNTIME_OUTPUT_TOKENS) {
        Err(KwpError::quota("runtime.output_tokens"))
    } else {
        Ok(())
    }
}

fn validate_runtime_sampling(
    thinking_level: Option<&str>,
    temperature: Option<f32>,
) -> Result<(), KwpError> {
    if thinking_level.is_some_and(|level| level.trim().is_empty()) {
        return Err(KwpError::BadRequest(
            "runtime thinking_level must not be empty".to_string(),
        ));
    }
    if temperature.is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value)) {
        return Err(KwpError::BadRequest(
            "runtime temperature must be between 0 and 1".to_string(),
        ));
    }
    Ok(())
}

fn ensure_model_preference_matches(
    preferences: Option<&Value>,
    selected_model: &str,
) -> Result<(), KwpError> {
    let Some(hints) = preferences.and_then(|value| value.get("hints")) else {
        return Ok(());
    };
    let hints = hints.as_array().ok_or_else(|| {
        KwpError::BadRequest("modelPreferences.hints must be an array".to_string())
    })?;
    if hints.is_empty()
        || hints
            .iter()
            .any(|hint| hint.get("name").and_then(Value::as_str) == Some(selected_model))
    {
        Ok(())
    } else {
        Err(KwpError::denied("runtime.model"))
    }
}

fn kwp_runtime_prompt(messages: &Value) -> Result<String, KwpError> {
    let messages = messages
        .as_array()
        .ok_or_else(|| KwpError::BadRequest("runtime messages must be an array".to_string()))?;
    let mut lines = Vec::with_capacity(messages.len());
    for message in messages {
        let role = message
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("user");
        let content = message
            .get("content")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                KwpError::BadRequest("runtime message content must be an array".to_string())
            })?;
        let text = content
            .iter()
            .filter_map(kwp_text_content)
            .collect::<Vec<_>>();
        if text.is_empty() {
            return Err(KwpError::BadRequest(
                "runtime message has no text content".to_string(),
            ));
        }
        lines.push(format!("{role}: {}", text.join("\n")));
    }
    if lines.is_empty() {
        Err(KwpError::BadRequest(
            "runtime messages must not be empty".to_string(),
        ))
    } else {
        Ok(lines.join("\n\n"))
    }
}

fn kwp_text_content(content: &Value) -> Option<&str> {
    (content.get("type").and_then(Value::as_str) == Some("text"))
        .then(|| content.get("text").and_then(Value::as_str))
        .flatten()
}

fn worker_runtime_response(
    response: crate::runtime::AgentQueryResponse,
    shape: WorkerRuntimeResponseShape,
) -> Result<Value, KwpError> {
    match shape {
        WorkerRuntimeResponseShape::Agent => serde_json::to_value(response),
        WorkerRuntimeResponseShape::Kwp => Ok(serde_json::json!({
            "content": [{ "type": "text", "text": response.text }],
            "stopReason": response.stop_reason,
        })),
    }
    .map_err(|error| KwpError::Internal(error.to_string()))
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
    mcp_bytes: BTreeMap<String, u64>,
    mcp_host: HostMcpBroker,
    fuzz_jobs: u32,
    fuzz_host: HostFuzzExecutor,
    recorded_artifacts: Vec<ArtifactRef>,
    artifact_bytes: u64,
    created_findings: usize,
    deadline: Instant,
    epoch: u64,
    initializing: bool,
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

    fn handle_worker_request_inner(
        &mut self,
        method: String,
        params: Value,
    ) -> Result<Value, KwpError> {
        self.ensure_unsettled()?;
        ensure_tool_execution_active(self.context)?;
        self.ensure_before_deadline()?;
        self.ensure_invocation_param(&params)?;
        self.ensure_init_capability(&method)?;
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

    fn ensure_init_capability(&self, method: &str) -> Result<(), KwpError> {
        if !self.initializing {
            return Ok(());
        }
        if self.module.grant.init_capabilities == InitCapabilities::FsRead
            && method == METHOD_FS_READ
        {
            return Ok(());
        }
        Err(KwpError::denied("initialize.capability"))
    }

    fn handle_fs_read(&mut self, params: Value) -> Result<Value, KwpError> {
        let request: WorkerFsReadRequest = serde_json::from_value(params)
            .map_err(|error| KwpError::BadRequest(error.to_string()))?;
        validate_broker_fs_path(request.scope, &request.path)?;
        let Some(grant) = self.module.grant.fs_scope(request.scope).cloned() else {
            return Err(KwpError::denied("fs"));
        };
        let root = self.scope_root(request.scope)?;
        let path = resolve_read_path(&root, &request.path)?;
        let remaining = remaining_fs_bytes(&self.fs_access, &grant);
        let read = read_fs_range(
            &path,
            request.offset.unwrap_or(0),
            request.length,
            remaining,
        )?;
        self.reserve_fs_access(&grant, &request.path, read.data.len() as u64)?;
        Ok(serde_json::json!({
            "dataBase64": BASE64.encode(read.data),
            "eof": read.eof,
        }))
    }

    fn handle_fs_write(&mut self, params: Value) -> Result<Value, KwpError> {
        let request: WorkerFsWriteRequest = serde_json::from_value(params)
            .map_err(|error| KwpError::BadRequest(error.to_string()))?;
        validate_broker_fs_path(request.scope, &request.path)?;
        let Some(grant) = self
            .module
            .grant
            .fs_scope(request.scope)
            .filter(|grant| grant.mode == FsMode::Rw && request.scope != FsScope::Input)
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
        write_fs_file_no_follow(&path, &data, request.append.unwrap_or(false))?;
        Ok(serde_json::json!({ "bytesWritten": data.len() }))
    }

    fn handle_fs_list(&mut self, params: Value) -> Result<Value, KwpError> {
        let request: WorkerFsPathRequest = serde_json::from_value(params)
            .map_err(|error| KwpError::BadRequest(error.to_string()))?;
        validate_broker_fs_path(request.scope, &request.path)?;
        let Some(grant) = self.module.grant.fs_scope(request.scope).cloned() else {
            return Err(KwpError::denied("fs"));
        };
        self.reserve_fs_access(&grant, &request.path, 0)?;
        let root = self.scope_root(request.scope)?;
        let path = resolve_read_path(&root, &request.path)?;
        let entries = fs::read_dir(&path)
            .map_err(|error| KwpError::Internal(error.to_string()))?
            .map(|entry| {
                fs_list_entry(entry.map_err(|error| KwpError::Internal(error.to_string()))?)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(serde_json::json!({ "entries": entries }))
    }

    fn handle_fs_stat(&mut self, params: Value) -> Result<Value, KwpError> {
        let request: WorkerFsPathRequest = serde_json::from_value(params)
            .map_err(|error| KwpError::BadRequest(error.to_string()))?;
        validate_broker_fs_path(request.scope, &request.path)?;
        let Some(grant) = self.module.grant.fs_scope(request.scope).cloned() else {
            return Err(KwpError::denied("fs"));
        };
        self.reserve_fs_access(&grant, &request.path, 0)?;
        let root = self.scope_root(request.scope)?;
        let path = resolve_read_path(&root, &request.path)?;
        let metadata =
            fs::metadata(&path).map_err(|error| KwpError::Internal(error.to_string()))?;
        Ok(fs_metadata_json(&metadata))
    }

    fn handle_fs_remove(&mut self, params: Value) -> Result<Value, KwpError> {
        let request: WorkerFsPathRequest = serde_json::from_value(params)
            .map_err(|error| KwpError::BadRequest(error.to_string()))?;
        validate_broker_fs_path(request.scope, &request.path)?;
        let Some(grant) = self
            .module
            .grant
            .fs_scope(request.scope)
            .filter(|grant| grant.mode == FsMode::Rw && request.scope != FsScope::Input)
            .cloned()
        else {
            return Err(KwpError::denied("fs.remove"));
        };
        self.reserve_fs_access(&grant, &request.path, 0)?;
        let root = self.scope_root(request.scope)?;
        let path = resolve_remove_path(&root, &request.path)?;
        let metadata =
            fs::metadata(&path).map_err(|error| KwpError::Internal(error.to_string()))?;
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
        let run_cost_usd = kwp_run_cost(&self.run_id)?;
        if grant.max_cost_usd_per_invocation <= 0.0
            || grant.max_cost_usd_per_run <= 0.0
            || self.runtime_cost_usd >= grant.max_cost_usd_per_invocation
            || run_cost_usd >= grant.max_cost_usd_per_run
        {
            return Err(KwpError::RuntimeBudget);
        }
        let Some(runtime) = self.runtime else {
            return Err(KwpError::denied("runtime.unavailable"));
        };
        let cwd = worker_runtime_cwd(self.module, self.context);
        let prepared = prepare_worker_runtime_request(
            &params,
            grant,
            self.context.config.model.as_deref(),
            &cwd,
        )?;
        let control = crate::runtime::AgentQueryControl::new(None, Some(self.deadline));
        let response = runtime
            .query_blocking_controlled(prepared.query, control.clone())
            .map_err(|error| controlled_runtime_error(&control, error))?;
        let run_cost_usd = record_kwp_run_cost(&self.run_id, response.cost_usd)?;
        self.runtime_cost_usd += response.cost_usd;
        if self.runtime_cost_usd > grant.max_cost_usd_per_invocation
            || run_cost_usd > grant.max_cost_usd_per_run
        {
            return Err(KwpError::RuntimeBudget);
        }
        worker_runtime_response(response, prepared.response_shape)
    }

    fn handle_artifacts_record(&mut self, params: Value) -> Result<Value, KwpError> {
        let Some(grant) = self
            .module
            .grant
            .artifacts
            .as_ref()
            .filter(|grant| grant.write)
        else {
            return Err(KwpError::denied("artifacts.write"));
        };
        let artifacts = artifacts_from_params(&params)?;
        let artifacts = self.verified_artifacts(grant, artifacts)?;
        self.recorded_artifacts.extend(artifacts.iter().cloned());
        Ok(serde_json::json!({ "artifacts": artifacts }))
    }

    fn handle_findings_create(&mut self, params: Value) -> Result<Value, KwpError> {
        let Some(grant) = self
            .module
            .grant
            .findings
            .as_ref()
            .filter(|grant| grant.create)
        else {
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
        let next_finding_count = self
            .created_findings
            .checked_add(findings.len())
            .ok_or_else(|| KwpError::quota("findings.count"))?;
        if grant
            .max_per_invocation
            .is_some_and(|max| next_finding_count > max as usize)
        {
            return Err(KwpError::quota("findings.count"));
        }
        ensure_finding_severities_allowed(grant, &findings)?;
        self.record_findings_run(store)?;
        for finding in &findings {
            store
                .insert_finding(&self.run_id.0, finding)
                .map_err(|error| KwpError::Internal(error.to_string()))?;
        }
        self.created_findings = next_finding_count;
        Ok(serde_json::json!({ "created": findings.len() }))
    }

    fn handle_mcp_call(&mut self, params: Value) -> Result<Value, KwpError> {
        let mut request: McpCallRequest = serde_json::from_value(params)
            .map_err(|error| KwpError::BadRequest(error.to_string()))?;
        let Some(grant) = self.module.grant.mcp_grant(&request.alias).cloned() else {
            return Err(KwpError::denied("mcp"));
        };
        ensure_supported_mcp_grant(&grant)?;
        if !grant.allows_tool(&request.tool) {
            return Err(KwpError::denied("mcp.tool"));
        }
        apply_mcp_grant_limits(&grant, &mut request.limits);
        self.reserve_mcp_call(&grant, &request)?;
        let Some(entry) = self.mcp_host.catalog().get(&request.alias) else {
            return Err(KwpError::denied("mcp.mount"));
        };
        if !entry.tools.contains_key(&request.tool) {
            return Err(KwpError::denied("mcp.catalog.tool"));
        }
        let session = self.mcp_session(&request.alias);
        let result = self.mcp_host.call_blocking(session, request)?;
        self.reserve_mcp_result(&grant, &result)?;
        let result = self.verified_mcp_result(&grant, result)?;
        self.recorded_artifacts
            .extend(result.artifacts.iter().cloned());
        serde_json::to_value(result).map_err(|error| KwpError::Internal(error.to_string()))
    }

    fn handle_fuzz_run(&mut self, params: Value) -> Result<Value, KwpError> {
        let request: FuzzRunRequest = serde_json::from_value(params)
            .map_err(|error| KwpError::BadRequest(error.to_string()))?;
        if request.invocation_id != self.invocation_id {
            return Err(KwpError::NoActiveInvocation);
        }
        let Some(grant) = self.module.grant.fuzz.clone() else {
            return Err(KwpError::denied("fuzz"));
        };
        if !grant.allows_engine(request.engine) {
            return Err(KwpError::denied("fuzz.engine"));
        }
        validate_fuzz_execution_request(&request)?;
        self.ensure_fuzz_artifacts_granted()?;
        validate_fuzz_request_paths(&request)?;
        self.reserve_fuzz_job(&grant, &request)?;
        let limits = request.limits.clone();
        let result = self.fuzz_host.run_blocking(self.event_origin(), request)?;
        let result = self.verified_fuzz_result(&grant, &limits, result)?;
        self.recorded_artifacts
            .extend(result.artifacts.iter().cloned());
        serde_json::to_value(result).map_err(|error| KwpError::Internal(error.to_string()))
    }

    fn handle_net_fetch(&mut self, params: Value) -> Result<Value, KwpError> {
        let Some(grant) = self.module.grant.net.as_ref() else {
            return Err(KwpError::denied("net"));
        };
        let request: NetFetchRequest = serde_json::from_value(params)
            .map_err(|error| KwpError::BadRequest(error.to_string()))?;
        let response_artifact = NetResponseArtifactRequest::from_request(&request);
        if response_artifact.is_some() {
            self.ensure_artifacts_granted()?;
        }
        let mut checked = validate_net_fetch_request(grant, request)?;
        checked.response_byte_limit =
            reserve_net_request_in_meter(&mut self.net_access, grant, &checked.request)?;
        let mut result = fetch_net_blocking(checked)?;
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
            let artifact =
                self.spill_net_response_artifact(response_artifact, &result.headers, &body)?;
            self.recorded_artifacts.push(artifact.clone());
            result.artifact = Some(artifact);
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
        if !self
            .module
            .grant
            .bus
            .produce
            .iter()
            .any(|pattern| pattern.matches(topic))
        {
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
        &mut self,
        grant: &ArtifactsGrant,
        artifacts: Vec<ArtifactRef>,
    ) -> Result<Vec<ArtifactRef>, KwpError> {
        validate_artifact_refs(&artifacts)?;
        let root = self.artifact_root();
        verify_artifact_refs(&root, grant, &mut self.artifact_bytes, artifacts)
    }

    fn verified_mcp_result(
        &mut self,
        grant: &McpGrant,
        mut result: McpCallResult,
    ) -> Result<McpCallResult, KwpError> {
        validate_mcp_result(result.clone())?;
        let artifact_grant = ArtifactsGrant {
            write: true,
            max_bytes_per_invocation: grant.max_artifacts_bytes_per_invocation,
        };
        result.artifacts = verify_artifact_refs(
            &self.artifact_root(),
            &artifact_grant,
            &mut self.artifact_bytes,
            result.artifacts,
        )?;
        Ok(result)
    }

    fn verified_fuzz_result(
        &mut self,
        grant: &FuzzGrant,
        limits: &FuzzLimits,
        mut result: FuzzRunResult,
    ) -> Result<FuzzRunResult, KwpError> {
        validate_fuzz_result(result.clone(), limits)?;
        let artifact_grant = self.fuzz_artifact_grant(grant)?;
        result.artifacts = verify_artifact_refs(
            &self.artifact_root(),
            &artifact_grant,
            &mut self.artifact_bytes,
            result.artifacts,
        )?;
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
        &mut self,
        request: NetResponseArtifactRequest,
        headers: &BTreeMap<String, String>,
        body: &[u8],
    ) -> Result<ArtifactRef, KwpError> {
        let root = self.artifact_root();
        let grant = self.required_artifact_grant()?.clone();
        spill_net_response_artifact(
            &root,
            &grant,
            &mut self.artifact_bytes,
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

    fn reserve_mcp_result(
        &mut self,
        grant: &McpGrant,
        result: &McpCallResult,
    ) -> Result<(), KwpError> {
        let bytes = serde_json::to_vec(result)
            .map_err(|error| KwpError::Internal(error.to_string()))?
            .len() as u64;
        let used = self.mcp_bytes.entry(grant.alias.clone()).or_default();
        *used = used
            .checked_add(bytes)
            .ok_or_else(|| KwpError::quota("mcp.bytes"))?;
        check_u64(Some(*used), grant.max_bytes_per_invocation, "mcp.bytes")
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

    fn record_broker_decision(
        &self,
        event: &str,
        result: &Result<Value, KwpError>,
    ) -> Result<(), KwpError> {
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
        let Some(target) = self.context.workspace.map(|workspace| workspace.root()) else {
            return Ok(());
        };
        let _guard = KWP_AUDIT_LOCK
            .get_or_init(|| StdMutex::new(()))
            .lock()
            .map_err(|_| KwpError::Internal("KWP audit lock was poisoned".to_string()))?;
        let path = writable_kwp_run_artifact_path(target, &self.run_id.0, "kwp-audit.jsonl")?;
        let anchor_path =
            writable_kwp_run_artifact_path(target, &self.run_id.0, KWP_AUDIT_ANCHOR_FILE)?;
        let records = read_anchored_kwp_audit_log(&path, &anchor_path)?;
        let prev = records.last().map(|record| record.hash.clone());
        let record = append_kwp_audit_log_record(
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
        )?;
        write_kwp_audit_anchor(&anchor_path, records.len() + 1, record.hash)
    }

    fn record_bus_event(&self, topic: String, payload: Value) -> Result<(), KwpError> {
        let Some(target) = self.context.workspace.map(|workspace| workspace.root()) else {
            return Err(KwpError::denied("bus.unavailable"));
        };
        let path = writable_kwp_run_artifact_path(target, &self.run_id.0, "kwp-bus.jsonl")?;
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

    fn attach_host_metrics(&self, mut result: Value) -> Value {
        sanitize_worker_result_value(&mut result);
        let Value::Object(ref mut object) = result else {
            return result;
        };
        let data = object
            .entry("data")
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if !data.is_object() {
            *data = Value::Object(serde_json::Map::new());
        }
        let Some(data) = data.as_object_mut() else {
            return result;
        };
        if !self.recorded_artifacts.is_empty() {
            data.insert(
                "artifacts".to_string(),
                serde_json::to_value(&self.recorded_artifacts).unwrap_or(Value::Array(Vec::new())),
            );
        }
        data.insert(
            "kwp".to_string(),
            serde_json::json!({
                "runtimeCostUsd": self.runtime_cost_usd,
                "invocationId": self.invocation_id.0,
                "runId": self.run_id.0,
                "moduleDigest": self.module.digest.0,
                "createdFindings": self.created_findings,
            }),
        );
        result
    }
}

fn controlled_runtime_error(
    control: &crate::runtime::AgentQueryControl,
    error: anyhow::Error,
) -> KwpError {
    if control.is_expired() {
        KwpError::Deadline
    } else if control.is_cancelled() {
        KwpError::NoActiveInvocation
    } else {
        KwpError::Internal(error.to_string())
    }
}

fn sanitize_worker_result_value(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.retain(|key, _| !is_privileged_worker_result_key(key));
            for value in object.values_mut() {
                sanitize_worker_result_value(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                sanitize_worker_result_value(value);
            }
        }
        _ => {}
    }
}

fn is_privileged_worker_result_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();
    normalized == "cost"
        || normalized.starts_with("cost")
        || normalized.ends_with("cost")
        || normalized.contains("costusd")
        || matches!(
            normalized.as_str(),
            "artifacts" | "findings" | "kwp" | "kuzushi" | "usage"
        )
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

fn module_data_root(
    module: &VerifiedModule,
    ctx: &crate::modules::ToolExecutionContext<'_>,
) -> PathBuf {
    let digest = module.digest.0.replace([':', '/', '\\'], "_");
    if let Some(workspace) = ctx.workspace {
        return workspace
            .state_dir()
            .join("kwp")
            .join("modules")
            .join(digest);
    }
    module.module_root.join(".kuzushi").join("kwp").join(digest)
}

fn resolve_read_path(root: &Path, path: &str) -> Result<PathBuf, KwpError> {
    validate_relative_path(path).map_err(|_| KwpError::denied("fs.path"))?;
    let root = canonical_or_create_root(root)?;
    let candidate = root.join(path);
    ensure_no_symlink_components(&root, &candidate)?;
    let canonical = fs::canonicalize(&candidate)
        .map_err(|error| KwpError::denied(format!("fs.path:{error}")))?;
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
    ensure_no_symlink_components(&root, &candidate)?;
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
    ensure_no_symlink_components(&root, &candidate)?;
    let canonical = fs::canonicalize(&candidate)
        .map_err(|error| KwpError::denied(format!("fs.path:{error}")))?;
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

fn ensure_no_symlink_components(root: &Path, candidate: &Path) -> Result<(), KwpError> {
    let relative = candidate
        .strip_prefix(root)
        .map_err(|_| KwpError::denied("fs.path"))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(KwpError::denied("fs.path"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(KwpError::Internal(error.to_string())),
        }
    }
    Ok(())
}

fn fs_list_entry(entry: fs::DirEntry) -> Result<Value, KwpError> {
    let file_type = entry
        .file_type()
        .map_err(|error| KwpError::Internal(error.to_string()))?;
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

fn read_fs_range(
    path: &Path,
    offset: u64,
    requested: Option<u64>,
    remaining: u64,
) -> Result<FsReadResult, KwpError> {
    if remaining == 0 {
        return Err(KwpError::quota("fs.bytes"));
    }
    let mut file =
        open_fs_read_no_follow(path).map_err(|error| KwpError::Internal(error.to_string()))?;
    let file_len = file
        .metadata()
        .map_err(|error| KwpError::Internal(error.to_string()))?
        .len();
    file.seek(SeekFrom::Start(offset))
        .map_err(|error| KwpError::Internal(error.to_string()))?;
    let limit = requested.unwrap_or(remaining).min(remaining);
    let mut data = Vec::new();
    file.take(limit)
        .read_to_end(&mut data)
        .map_err(|error| KwpError::Internal(error.to_string()))?;
    Ok(FsReadResult {
        eof: offset.saturating_add(data.len() as u64) >= file_len,
        data,
    })
}

#[cfg(unix)]
fn open_fs_read_no_follow(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_fs_read_no_follow(path: &Path) -> std::io::Result<fs::File> {
    reject_final_symlink(path)?;
    fs::File::open(path)
}

#[cfg(unix)]
fn write_fs_file_no_follow(path: &Path, data: &[u8], append: bool) -> Result<(), KwpError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options
        .create(true)
        .write(true)
        .append(append)
        .truncate(!append)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .map_err(|error| KwpError::denied(format!("fs.path:{error}")))?;
    file.write_all(data)
        .map_err(|error| KwpError::Internal(error.to_string()))
}

#[cfg(not(unix))]
fn write_fs_file_no_follow(path: &Path, data: &[u8], append: bool) -> Result<(), KwpError> {
    reject_final_symlink(path).map_err(|error| KwpError::denied(format!("fs.path:{error}")))?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(append)
        .truncate(!append)
        .open(path)
        .map_err(|error| KwpError::Internal(error.to_string()))?;
    file.write_all(data)
        .map_err(|error| KwpError::Internal(error.to_string()))
}

#[cfg(not(unix))]
fn reject_final_symlink(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "path is a symlink",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
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
    total_bytes: &mut u64,
    artifacts: Vec<ArtifactRef>,
) -> Result<Vec<ArtifactRef>, KwpError> {
    artifacts
        .into_iter()
        .map(|artifact| verify_artifact_ref(root, grant, total_bytes, artifact))
        .collect()
}

fn verify_artifact_ref(
    root: &Path,
    grant: &ArtifactsGrant,
    total_bytes: &mut u64,
    mut artifact: ArtifactRef,
) -> Result<ArtifactRef, KwpError> {
    ensure_artifact_media_type(&artifact)?;
    let path = resolve_read_path(root, &artifact.path)?;
    let bytes = read_artifact_bytes(&path, grant, *total_bytes)?;
    reserve_artifact_bytes(total_bytes, bytes.len() as u64)?;
    let actual = sha256_digest(&bytes).0;
    ensure_artifact_digest_matches(artifact.sha256.as_deref(), &actual)?;
    artifact.sha256 = Some(actual);
    Ok(artifact)
}

fn ensure_artifact_media_type(artifact: &ArtifactRef) -> Result<(), KwpError> {
    if artifact.media_type.trim().is_empty() {
        return Err(KwpError::BadRequest(
            "artifact mediaType omitted".to_string(),
        ));
    }
    Ok(())
}

fn read_artifact_bytes(
    path: &Path,
    grant: &ArtifactsGrant,
    used_bytes: u64,
) -> Result<Vec<u8>, KwpError> {
    let file = open_fs_read_no_follow(&path)
        .map_err(|error| KwpError::denied(format!("artifact.path:{error}")))?;
    let size = file
        .metadata()
        .map_err(|error| KwpError::Internal(error.to_string()))?
        .len();
    ensure_artifact_byte_budget(grant, used_bytes, size)?;
    let read_limit = effective_artifact_byte_limit(grant)
        .saturating_sub(used_bytes)
        .saturating_add(1);
    let mut bytes = Vec::new();
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|error| KwpError::Internal(error.to_string()))?;
    ensure_artifact_byte_budget(grant, used_bytes, bytes.len() as u64)?;
    Ok(bytes)
}

fn reserve_artifact_bytes(total_bytes: &mut u64, bytes: u64) -> Result<(), KwpError> {
    *total_bytes = total_bytes
        .checked_add(bytes)
        .ok_or_else(|| KwpError::quota("artifacts.bytes"))?;
    Ok(())
}

fn ensure_artifact_digest_matches(declared: Option<&str>, actual: &str) -> Result<(), KwpError> {
    if declared.is_some_and(|declared| declared != actual) {
        return Err(KwpError::denied("artifact.sha256"));
    }
    Ok(())
}

fn ensure_artifact_byte_budget(
    grant: &ArtifactsGrant,
    used: u64,
    additional: u64,
) -> Result<(), KwpError> {
    let next = used
        .checked_add(additional)
        .ok_or_else(|| KwpError::quota("artifacts.bytes"))?;
    check_u64(
        Some(next),
        Some(effective_artifact_byte_limit(grant)),
        "artifacts.bytes",
    )
}

fn effective_artifact_byte_limit(grant: &ArtifactsGrant) -> u64 {
    grant
        .max_bytes_per_invocation
        .unwrap_or(KWP_MAX_ARTIFACT_BYTES)
        .min(KWP_MAX_ARTIFACT_BYTES)
}

fn worker_findings_from_value(
    value: &Value,
    default_tool: &str,
) -> Result<Vec<crate::findings::Finding>, KwpError> {
    let Some(findings) = value.as_array() else {
        return Err(KwpError::BadRequest(
            "findings must be an array".to_string(),
        ));
    };
    findings
        .iter()
        .cloned()
        .map(|finding| worker_finding_from_value(finding, default_tool))
        .collect()
}

fn worker_finding_from_value(
    value: Value,
    default_tool: &str,
) -> Result<crate::findings::Finding, KwpError> {
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
    if findings
        .iter()
        .all(|finding| severity_allowed(grant, finding.severity))
    {
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

fn fetch_net_blocking(checked: ValidatedNetFetch) -> Result<NetFetchResult, KwpError> {
    let client = build_net_client(&checked)?;
    let request = build_net_request(&client, &checked.request)?;
    let response = request
        .send()
        .map_err(|error| KwpError::Internal(error.to_string()))?;
    net_fetch_result(response, checked.response_byte_limit)
}

fn build_net_client(checked: &ValidatedNetFetch) -> Result<reqwest::blocking::Client, KwpError> {
    let timeout = checked
        .request
        .timeout_ms
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_secs(30));
    reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .resolve(&checked.endpoint.host, checked.pinned_addr)
        .build()
        .map_err(|error| KwpError::Internal(error.to_string()))
}

fn build_net_request(
    client: &reqwest::blocking::Client,
    input: &NetFetchRequest,
) -> Result<reqwest::blocking::RequestBuilder, KwpError> {
    let method = reqwest::Method::from_bytes(input.method.as_bytes())
        .map_err(|error| KwpError::BadRequest(error.to_string()))?;
    let mut request = client.request(method, &input.url);
    for (name, value) in &input.headers {
        let header_name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|error| KwpError::BadRequest(error.to_string()))?;
        let header_value = reqwest::header::HeaderValue::from_str(value)
            .map_err(|error| KwpError::BadRequest(error.to_string()))?;
        request = request.header(header_name, header_value);
    }
    if let Some(body) = input.body_base64.as_ref() {
        let body = BASE64
            .decode(body.as_bytes())
            .map_err(|error| KwpError::BadRequest(error.to_string()))?;
        request = request.body(body);
    }
    Ok(request)
}

fn net_fetch_result(
    response: reqwest::blocking::Response,
    grant_limit: Option<u64>,
) -> Result<NetFetchResult, KwpError> {
    let status = response.status().as_u16();
    let headers = response_headers(response.headers());
    let response_byte_limit = effective_net_response_limit(grant_limit);
    check_u64(
        response.content_length(),
        Some(response_byte_limit),
        "net.bytes",
    )?;
    let body = read_net_response_body(response, Some(response_byte_limit))?;
    Ok(NetFetchResult {
        status,
        headers,
        body_base64: Some(BASE64.encode(body)),
        artifact: None,
    })
}

fn effective_net_response_limit(grant_limit: Option<u64>) -> u64 {
    grant_limit
        .unwrap_or(KWP_MAX_NETWORK_RESPONSE_BYTES)
        .min(KWP_MAX_NETWORK_RESPONSE_BYTES)
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
    pub fn new(
        trust: Arc<LockfileTrustVerifier>,
        executors: BTreeMap<ExecutorTier, Arc<dyn WorkerExecutor>>,
    ) -> Self {
        Self { trust, executors }
    }

    pub async fn spawn_verified(
        &self,
        specifier: &str,
        mode: WorkerMode,
    ) -> Result<SpawnedWorker, KwpError> {
        let module = self
            .trust
            .verify(specifier)
            .await
            .map_err(|error| KwpError::denied(format!("trust.{error}")))?;
        let executor = self
            .executors
            .get(&module.tier)
            .ok_or_else(|| KwpError::denied("executor"))?;
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
        async fn read(
            &self,
            _scope: FsScope,
            _path: &str,
            _offset: u64,
            _length: Option<u64>,
        ) -> Result<FsReadResult, KwpError> {
            Ok(FsReadResult {
                data: Vec::new(),
                eof: true,
            })
        }

        async fn write(
            &self,
            _scope: FsScope,
            _path: &str,
            data: Vec<u8>,
            _append: bool,
        ) -> Result<u64, KwpError> {
            Ok(data.len() as u64)
        }
    }

    #[async_trait]
    impl NetBackend for Effects {
        async fn fetch(&self, _request: NetFetchRequest) -> Result<NetFetchResult, KwpError> {
            Ok(NetFetchResult {
                status: 200,
                headers: BTreeMap::new(),
                body_base64: None,
                artifact: None,
            })
        }
    }

    #[async_trait]
    impl RuntimeBackend for Effects {
        async fn query(
            &self,
            _request: RuntimeQueryRequest,
        ) -> Result<RuntimeQueryResult, KwpError> {
            Ok(RuntimeQueryResult {
                completion: json!({}),
                cost_usd: 0.01,
            })
        }
    }

    #[async_trait]
    impl BusBackend for Effects {
        async fn publish(
            &self,
            _origin: EventOrigin,
            _topic: String,
            _payload: Value,
        ) -> Result<(), KwpError> {
            Ok(())
        }
    }

    #[async_trait]
    impl FindingBackend for Effects {
        async fn create(
            &self,
            _origin: EventOrigin,
            findings: Vec<Value>,
        ) -> Result<FindingsCreateResult, KwpError> {
            Ok(FindingsCreateResult {
                created: findings.len(),
            })
        }
    }

    #[async_trait]
    impl ArtifactBackend for Effects {
        async fn record(
            &self,
            _origin: EventOrigin,
            artifacts: Vec<ArtifactRef>,
        ) -> Result<Vec<ArtifactRef>, KwpError> {
            validate_artifact_refs(&artifacts)?;
            Ok(artifacts)
        }
    }

    #[async_trait]
    impl McpBackend for Effects {
        async fn call(
            &self,
            session: McpSessionKey,
            _request: McpCallRequest,
        ) -> Result<McpCallResult, KwpError> {
            self.mcp_sessions.lock().await.push(session);
            Ok(McpCallResult {
                structured_content: json!({}),
                artifacts: Vec::new(),
            })
        }
    }

    #[async_trait]
    impl FuzzBackend for Effects {
        async fn run(
            &self,
            _origin: EventOrigin,
            request: FuzzRunRequest,
        ) -> Result<FuzzRunResult, KwpError> {
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
                mode: McpGrantMode::Dedicated,
                max_calls_per_invocation: None,
                max_cpu_seconds_per_invocation: None,
                max_bytes_per_invocation: None,
                max_artifacts_bytes_per_invocation: None,
                workspace: McpWorkspaceMode::ReadWrite,
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
        let verifier = LockfileTrustVerifier::new(
            Arc::new(lockfile),
            Arc::new(FixedResolver(bundle)),
            Arc::new(AllowSignatures),
        );

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
        let verifier = LockfileTrustVerifier::new(
            Arc::new(lockfile_with(entry)),
            Arc::new(FixedResolver(bundle)),
            Arc::new(AllowSignatures),
        );

        let error = verifier.verify("package:agentic-fuzz").await.unwrap_err();

        assert_eq!(error, TrustError::Revoked);
    }

    #[tokio::test]
    async fn trust_verifier_rejects_descriptor_hash_drift() {
        let bundle = worker_bundle();
        let mut entry = approved_entry(&bundle);
        entry.descriptor_hash = "sha256:old-descriptor".to_string();
        let verifier = LockfileTrustVerifier::new(
            Arc::new(lockfile_with(entry)),
            Arc::new(FixedResolver(bundle)),
            Arc::new(AllowSignatures),
        );

        let error = verifier.verify("package:agentic-fuzz").await.unwrap_err();

        assert_eq!(error, TrustError::DescriptorHashMismatch);
    }

    #[test]
    fn lockfile_round_trips_json_and_validates_digest_keys() {
        let bundle = worker_bundle();
        let mut lockfile = lockfile_with(approved_entry(&bundle));
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("kuzushi.lock");

        lockfile.write_json(&path).unwrap();
        let read = KuzushiLockfile::read_json(&path).unwrap();

        assert_eq!(read, lockfile);

        lockfile.modules.get_mut(&bundle.digest.0).unwrap().revoked = true;
        lockfile.write_json(&path).unwrap();
        let replaced = KuzushiLockfile::read_json(&path).unwrap();
        let temp_files = fs::read_dir(temp.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .collect::<Vec<_>>();

        assert_eq!(replaced, lockfile);
        assert!(temp_files.is_empty(), "atomic write left temp siblings");
    }

    #[test]
    fn lockfile_rejects_digest_key_mismatch() {
        let bundle = worker_bundle();
        let mut lockfile = KuzushiLockfile::default();
        lockfile
            .modules
            .insert("sha256:wrong".to_string(), approved_entry(&bundle));

        let error = lockfile
            .write_json(tempfile::NamedTempFile::new().unwrap().path())
            .unwrap_err();

        assert_eq!(
            error,
            TrustError::LockfileDigestKeyMismatch {
                key: "sha256:wrong".to_string(),
                entry_digest: "sha256:abc".to_string(),
            }
        );
    }

    #[test]
    fn grant_rejects_misspelled_capability_fields() {
        let top_level = serde_json::from_value::<Grant>(json!({
            "artifact": { "write": true }
        }))
        .unwrap_err();
        let nested = serde_json::from_value::<Grant>(json!({
            "mcp": [{
                "alias": "symcc",
                "tools": ["compile"],
                "mode": "shared",
                "workspace": "scratch-only",
                "maxCallsPerInvocaton": 1
            }]
        }))
        .unwrap_err();

        assert!(top_level.to_string().contains("artifact"));
        assert!(nested.to_string().contains("maxCallsPerInvocaton"));
    }

    #[test]
    fn grant_and_lockfile_use_schema_facing_json_names() {
        let bundle = worker_bundle();
        let mut entry = approved_entry(&bundle);
        entry.grant.exec = Some(vec![ExecGrant {
            bin: "tool".to_string(),
            argv_allow: vec!["--version".to_string()],
        }]);

        let grant = serde_json::to_value(&entry.grant).unwrap();
        let entry = serde_json::to_value(&entry).unwrap();

        assert_eq!(
            grant.pointer("/exec/0/argvAllow"),
            Some(&json!(["--version"]))
        );
        assert_eq!(grant["initCapabilities"], json!("fs-read"));
        assert_eq!(entry["moduleId"], json!("agentic-fuzz"));
        assert_eq!(entry["descriptorHash"], json!("sha256:descriptor"));
        assert!(entry.get("signatureChain").is_some());
    }

    #[test]
    fn default_grant_omits_optional_capabilities_in_json() {
        let value = serde_json::to_value(Grant::default()).unwrap();
        let object = value.as_object().unwrap();

        for field in ["net", "runtime", "findings", "artifacts", "fuzz", "exec"] {
            assert!(
                !object.contains_key(field),
                "unexpected optional field {field}: {value}"
            );
        }
        assert_eq!(
            serde_json::from_value::<Grant>(value).unwrap(),
            Grant::default()
        );
    }

    #[test]
    fn grant_rejects_unsupported_input_write_and_broker_modes() {
        let input_write = Grant {
            fs: vec![FsScopeGrant {
                scope: FsScope::Input,
                mode: FsMode::Rw,
                max_bytes: None,
                max_files: None,
            }],
            ..Grant::default()
        };
        let mut shared_mcp = mcp_grant(&["compile"]);
        shared_mcp.mcp[0].mode = McpGrantMode::Shared;

        assert!(matches!(
            input_write.validate(),
            Err(TrustError::LockfileInvalid(_))
        ));
        assert!(matches!(
            shared_mcp.validate(),
            Err(TrustError::LockfileInvalid(_))
        ));
        assert!(!input_write.allows_fs_write(FsScope::Input));
    }

    #[test]
    fn grant_rejects_non_finite_and_negative_runtime_budgets() {
        for invalid in [f64::NAN, f64::INFINITY, -0.01] {
            let grant = Grant {
                runtime: Some(RuntimeGrant {
                    max_cost_usd_per_invocation: invalid,
                    max_cost_usd_per_run: 1.0,
                    models: None,
                }),
                ..Grant::default()
            };
            assert!(matches!(
                grant.validate(),
                Err(TrustError::LockfileInvalid(_))
            ));
        }
        let invalid_run = Grant {
            runtime: Some(RuntimeGrant {
                max_cost_usd_per_invocation: 1.0,
                max_cost_usd_per_run: f64::NEG_INFINITY,
                models: None,
            }),
            ..Grant::default()
        };
        assert!(matches!(
            invalid_run.validate(),
            Err(TrustError::LockfileInvalid(_))
        ));
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
    fn configured_signature_verifier_rejects_grant_widening_after_signing() {
        let bundle = worker_bundle();
        let mut entry = approved_entry(&bundle);
        sign_entry(&mut entry);
        entry.grant.artifacts = Some(ArtifactsGrant {
            write: true,
            max_bytes_per_invocation: Some(1024),
        });
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
            Digest(
                "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                    .to_string()
            )
        );
    }

    #[test]
    fn kwp_audit_log_integrity_detects_hash_tampering() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("kwp-audit.jsonl");
        let first =
            append_kwp_audit_log_record(&path, audit_body(None, "invocation.start")).unwrap();
        append_kwp_audit_log_record(&path, audit_body(Some(first.hash), "fs.write")).unwrap();
        let mut records = read_kwp_audit_log_path(&path).unwrap();

        let clean = kwp_audit_log_integrity(&records).unwrap();
        assert!(clean.ok, "{clean:?}");

        records[1].event = "net.fetch".to_string();
        let tampered = kwp_audit_log_integrity(&records).unwrap();

        assert!(!tampered.ok, "{tampered:?}");
        assert!(tampered.errors.iter().any(|error| error.field == "hash"));
    }

    #[test]
    fn anchored_audit_log_detects_deletion() {
        let tmp = tempfile::tempdir().unwrap();
        let path =
            writable_kwp_run_artifact_path(tmp.path(), "run-audit", "kwp-audit.jsonl").unwrap();
        let anchor =
            writable_kwp_run_artifact_path(tmp.path(), "run-audit", KWP_AUDIT_ANCHOR_FILE).unwrap();
        let record =
            append_kwp_audit_log_record(&path, audit_body(None, "invocation.start")).unwrap();
        write_kwp_audit_anchor(&anchor, 1, record.hash).unwrap();

        assert_eq!(
            read_kwp_audit_log(tmp.path(), "run-audit").unwrap().len(),
            1
        );
        fs::remove_file(path).unwrap();
        let error = read_kwp_audit_log(tmp.path(), "run-audit").unwrap_err();

        assert!(matches!(error, KwpError::Internal(message) if message.contains("missing")));
    }

    #[test]
    fn anchored_audit_log_detects_truncation() {
        let tmp = tempfile::tempdir().unwrap();
        let path =
            writable_kwp_run_artifact_path(tmp.path(), "run-audit", "kwp-audit.jsonl").unwrap();
        let anchor =
            writable_kwp_run_artifact_path(tmp.path(), "run-audit", KWP_AUDIT_ANCHOR_FILE).unwrap();
        let first =
            append_kwp_audit_log_record(&path, audit_body(None, "invocation.start")).unwrap();
        let second =
            append_kwp_audit_log_record(&path, audit_body(Some(first.hash), "invocation.end"))
                .unwrap();
        write_kwp_audit_anchor(&anchor, 2, second.hash).unwrap();
        let first_line = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .to_string();
        fs::write(&path, format!("{first_line}\n")).unwrap();

        let error = read_kwp_audit_log(tmp.path(), "run-audit").unwrap_err();

        assert!(matches!(error, KwpError::Internal(message) if message.contains("anchor")));
    }

    #[cfg(unix)]
    #[test]
    fn audit_paths_reject_symlinked_run_directories() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let initial =
            writable_kwp_run_artifact_path(tmp.path(), "run-audit", "kwp-audit.jsonl").unwrap();
        let run_dir = initial.parent().unwrap();
        fs::remove_dir(run_dir).unwrap();
        symlink(outside.path(), run_dir).unwrap();

        let error =
            writable_kwp_run_artifact_path(tmp.path(), "run-audit", "kwp-audit.jsonl").unwrap_err();

        assert!(matches!(error, KwpError::Internal(message) if message.contains("symlink")));
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

        let error =
            append_kwp_bus_event(&path, bus_event("topic.allowed", Value::Null)).unwrap_err();

        assert!(
            matches!(error, KwpError::Internal(message) if message.contains("target is not a file"))
        );
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
        request
            .headers
            .insert("Authorization".to_string(), "Bearer stolen".to_string());
        request
            .headers
            .insert("Cookie".to_string(), "sid=secret".to_string());
        request
            .headers
            .insert("X-Forwarded-For".to_string(), "127.0.0.1".to_string());
        request
            .headers
            .insert("Accept".to_string(), "application/json".to_string());

        let checked = validate_net_fetch_request(&grant, request).unwrap();

        assert_eq!(checked.request.headers.len(), 1);
        assert_eq!(
            checked.request.headers.get("Accept").map(String::as_str),
            Some("application/json")
        );
    }

    #[test]
    fn net_fetch_carries_the_validated_endpoint_into_transport() {
        let grant = net_grant(&["93.184.216.34:443"]);
        let checked =
            validate_net_fetch_request(&grant, net_request("https://93.184.216.34/resource"))
                .unwrap();

        assert_eq!(checked.endpoint.host, "93.184.216.34");
        assert_eq!(checked.pinned_addr, "93.184.216.34:443".parse().unwrap());
    }

    #[test]
    fn net_fetch_rejects_mixed_public_and_private_dns_results() {
        let addresses = vec![
            "93.184.216.34:443".parse().unwrap(),
            "10.0.0.1:443".parse().unwrap(),
        ];

        let error = validated_public_socket(addresses).unwrap_err();

        assert_eq!(error, KwpError::denied("net.ssr.ip"));
    }

    #[test]
    fn wildcard_host_patterns_require_a_subdomain_boundary() {
        let pattern = HostPattern("*.example.com:443".to_string());

        assert!(pattern.matches("api.example.com", 443));
        assert!(pattern.matches("deep.api.example.com", 443));
        assert!(!pattern.matches("example.com", 443));
        assert!(!pattern.matches("notexample.com", 443));
        assert!(!pattern.matches("api.example.com", 80));
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
        let body =
            read_net_response_body(std::io::Cursor::new(b"abcdef".to_vec()), Some(3)).unwrap_err();

        assert_eq!(body, KwpError::quota("net.bytes"));
    }

    #[test]
    fn net_response_body_reader_allows_body_at_limit() {
        let body = read_net_response_body(std::io::Cursor::new(b"abc".to_vec()), Some(3)).unwrap();

        assert_eq!(body, b"abc");
    }

    #[test]
    fn net_response_without_grant_limit_uses_absolute_host_cap() {
        assert_eq!(
            effective_net_response_limit(None),
            KWP_MAX_NETWORK_RESPONSE_BYTES
        );
        assert_eq!(effective_net_response_limit(Some(128)), 128);
        assert_eq!(
            effective_net_response_limit(Some(KWP_MAX_NETWORK_RESPONSE_BYTES + 1)),
            KWP_MAX_NETWORK_RESPONSE_BYTES
        );
    }

    #[test]
    fn net_response_artifact_spill_writes_and_hashes_body() {
        let tmp = tempfile::tempdir().unwrap();
        let grant = ArtifactsGrant {
            write: true,
            max_bytes_per_invocation: Some(64),
        };
        let headers = BTreeMap::from([("content-type".to_string(), "text/plain".to_string())]);
        let mut total_bytes = 0;

        let artifact = spill_net_response_artifact(
            tmp.path(),
            &grant,
            &mut total_bytes,
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
        assert_eq!(
            fs::read(tmp.path().join("net/response.txt")).unwrap(),
            b"brokered response"
        );
        assert_eq!(artifact.sha256, Some(sha256_digest(b"brokered response").0));
        assert_eq!(total_bytes, b"brokered response".len() as u64);
    }

    #[test]
    fn net_response_artifact_spill_denies_escape_and_quota() {
        let tmp = tempfile::tempdir().unwrap();
        let grant = ArtifactsGrant {
            write: true,
            max_bytes_per_invocation: Some(3),
        };
        let headers = BTreeMap::new();
        let mut total_bytes = 0;

        let escape = spill_net_response_artifact(
            tmp.path(),
            &grant,
            &mut total_bytes,
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
            &mut total_bytes,
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

    #[test]
    fn artifact_quota_is_cumulative_across_records() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("one.txt"), b"abc").unwrap();
        fs::write(tmp.path().join("two.txt"), b"def").unwrap();
        let grant = ArtifactsGrant {
            write: true,
            max_bytes_per_invocation: Some(5),
        };
        let mut total_bytes = 0;

        verify_artifact_ref(
            tmp.path(),
            &grant,
            &mut total_bytes,
            ArtifactRef {
                path: "one.txt".to_string(),
                media_type: "text/plain".to_string(),
                sha256: None,
            },
        )
        .unwrap();
        let error = verify_artifact_ref(
            tmp.path(),
            &grant,
            &mut total_bytes,
            ArtifactRef {
                path: "two.txt".to_string(),
                media_type: "text/plain".to_string(),
                sha256: None,
            },
        )
        .unwrap_err();

        assert_eq!(error, KwpError::quota("artifacts.bytes"));
        assert_eq!(total_bytes, 3);
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

    #[test]
    fn workspace_fs_broker_rejects_control_paths() {
        assert_eq!(
            validate_broker_fs_path(FsScope::Workspace, "kuzushi.lock").unwrap_err(),
            KwpError::denied("fs.control_path")
        );
        assert_eq!(
            validate_broker_fs_path(FsScope::Workspace, ".kuzushi/v3/config.toml").unwrap_err(),
            KwpError::denied("fs.control_path")
        );
        validate_broker_fs_path(FsScope::Input, "src/lib.rs").unwrap();
    }

    #[test]
    fn fs_range_read_is_bounded_before_allocation() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("large.txt");
        fs::write(&path, vec![b'x'; 1024]).unwrap();

        let result = read_fs_range(&path, 10, Some(500), 3).unwrap();

        assert_eq!(result.data, b"xxx");
        assert!(!result.eof);
    }

    #[cfg(unix)]
    #[test]
    fn broker_paths_reject_symlink_components_and_final_targets() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), b"secret").unwrap();
        symlink(outside.path(), tmp.path().join("linked")).unwrap();
        symlink(
            outside.path().join("secret.txt"),
            tmp.path().join("final.txt"),
        )
        .unwrap();

        assert_eq!(
            resolve_read_path(tmp.path(), "linked/secret.txt").unwrap_err(),
            KwpError::denied("fs.path")
        );
        assert!(matches!(
            write_fs_file_no_follow(tmp.path().join("final.txt").as_path(), b"overwrite", false),
            Err(KwpError::NotGranted(_))
        ));
        assert_eq!(
            fs::read(outside.path().join("secret.txt")).unwrap(),
            b"secret"
        );
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
        let line =
            encode_rpc_line(&RpcMessage::request(7, "initialize", json!({"grant": {}}))).unwrap();
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
        let error_line = encode_rpc_line(&RpcMessage::error_response(
            "req-2",
            KwpError::denied("mcp").into(),
        ))
        .unwrap();

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
        let error =
            decode_rpc_line(br#"{"jsonrpc":"1.0","id":1,"method":"initialize"}"#).unwrap_err();

        assert_eq!(
            error,
            KwpError::BadRequest("jsonrpc version must be 2.0".to_string())
        );
    }

    #[test]
    fn worker_stdout_rejects_messages_above_the_wire_limit() {
        let mut input = std::io::Cursor::new(vec![b'x'; KWP_MAX_MESSAGE_BYTES + 1]);

        let error = read_bounded_line(&mut input, "test worker", "rpc.message_bytes").unwrap_err();

        assert_eq!(error, KwpError::quota("rpc.message_bytes"));
    }

    #[test]
    fn fs_scope_accepts_sdk_module_data_alias_but_serializes_canonically() {
        let scope: FsScope = serde_json::from_value(json!("moduleData")).unwrap();

        assert_eq!(scope, FsScope::ModuleData);
        assert_eq!(serde_json::to_value(scope).unwrap(), json!("module-data"));
    }

    #[test]
    fn worker_initialize_descriptor_hash_projection_includes_module_visibility() {
        let initialize = json!({
            "module": {
                "id": "hidden-worker",
                "name": "Hidden Worker",
                "kind": "internal",
                "description": "hidden dynamic module"
            },
            "hidden": true,
            "tools": []
        });

        let descriptor = worker_initialize_descriptor(&initialize).unwrap();
        let projected = serde_json::to_value(descriptor).unwrap();

        assert_eq!(projected["hidden"], json!(true));
        assert_ne!(
            descriptor_hash_from_value(&projected).unwrap(),
            descriptor_hash_from_value(&json!({
                "module": initialize["module"],
                "hidden": false,
                "tools": []
            }))
            .unwrap()
        );
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

    #[test]
    fn worker_runtime_request_uses_only_host_model_and_cwd() {
        let grant = RuntimeGrant {
            max_cost_usd_per_invocation: 1.0,
            max_cost_usd_per_run: 2.0,
            models: Some(vec!["openai:gpt-5".to_string()]),
        };
        let cwd = Path::new("/host/selected/workspace");

        let prepared = prepare_worker_runtime_request(
            &json!({
                "request": {
                    "prompt": "inspect this",
                    "systemPrompt": "be precise",
                    "maxOutputTokens": 32
                }
            }),
            &grant,
            Some("openai:gpt-5"),
            cwd,
        )
        .unwrap();

        assert_eq!(prepared.query.model, "openai:gpt-5");
        assert_eq!(prepared.query.cwd, cwd);
        assert_eq!(prepared.query.prompt, "inspect this");
        assert!(prepared.query.tool_policy.tools.is_empty());
        assert!(!prepared.query.tool_policy.mcps);
        assert!(prepared.query.runtime_options.is_none());
    }

    #[test]
    fn worker_runtime_request_rejects_worker_host_policy_fields() {
        let grant = RuntimeGrant {
            max_cost_usd_per_invocation: 1.0,
            max_cost_usd_per_run: 2.0,
            models: Some(vec!["openai:gpt-5".to_string()]),
        };

        let error = prepare_worker_runtime_request(
            &json!({
                "request": {
                    "prompt": "inspect this",
                    "model": "attacker:model",
                    "cwd": "/tmp/attacker",
                    "toolPolicy": { "profile": "full" }
                }
            }),
            &grant,
            Some("openai:gpt-5"),
            Path::new("/host/selected/workspace"),
        )
        .err()
        .unwrap();
        assert!(matches!(error, KwpError::BadRequest(_)));
    }

    #[test]
    fn run_cost_ledger_is_shared_by_run_id() {
        let run_id = RunId(format!("ledger-{}", uuid::Uuid::new_v4()));

        assert_eq!(kwp_run_cost(&run_id).unwrap(), 0.0);
        assert_eq!(record_kwp_run_cost(&run_id, 0.25).unwrap(), 0.25);
        assert_eq!(record_kwp_run_cost(&run_id, 0.5).unwrap(), 0.75);
        assert_eq!(kwp_run_cost(&run_id).unwrap(), 0.75);
    }

    #[test]
    fn worker_result_sanitizer_removes_forged_host_metrics_recursively() {
        let mut value = json!({
            "ok": true,
            "forecast": "rain",
            "costUsd": 0.0,
            "data": {
                "artifacts": [{"path": "forged"}],
                "nested": {
                    "runtimeCostUsd": 0.0,
                    "findings": [{"id": "forged"}],
                    "usage": {"tokens": 1}
                }
            }
        });

        sanitize_worker_result_value(&mut value);

        assert_eq!(value["forecast"], json!("rain"));
        assert!(value.get("costUsd").is_none());
        assert!(value["data"].get("artifacts").is_none());
        assert!(value["data"]["nested"].get("runtimeCostUsd").is_none());
        assert!(value["data"]["nested"].get("findings").is_none());
        assert!(value["data"]["nested"].get("usage").is_none());
    }

    #[test]
    fn worker_message_wait_honors_external_cancellation() {
        let (_sender, receiver) = mpsc::channel();
        let cancellation = crate::scan::ScanCancellation::default();
        cancellation.cancel();

        let error = read_next_worker_message(
            &receiver,
            Instant::now() + Duration::from_secs(1),
            "module:tool",
            Some(&cancellation),
        )
        .unwrap_err();

        assert_eq!(error, KwpError::NoActiveInvocation);
    }

    #[tokio::test]
    async fn module_without_mcp_grant_cannot_call_mcp() {
        let effects = Arc::new(Effects::default());
        let broker = broker(effects.clone());
        let inv = invocation_for("agentic-fuzz", Grant::default());

        let error = broker
            .mcp_call(&inv, mcp_request("agentic-fuzz", "compile"))
            .await
            .unwrap_err();

        assert_eq!(error, KwpError::denied("mcp"));
        assert!(effects.mcp_sessions.lock().await.is_empty());
        assert_eq!(effects.audit.lock().await[0].decision, AuditDecision::Deny);
    }

    #[tokio::test]
    async fn mcp_grant_allows_only_listed_tools() {
        let effects = Arc::new(Effects::default());
        let broker = broker(effects.clone());
        let inv = invocation_for("binary-hunt", mcp_grant(&["compile"]));

        broker
            .mcp_call(&inv, mcp_request("binary-hunt", "compile"))
            .await
            .unwrap();
        let error = broker
            .mcp_call(&inv, mcp_request("binary-hunt", "export_corpus"))
            .await
            .unwrap_err();

        assert_eq!(error, KwpError::denied("mcp.tool"));
        assert_eq!(effects.mcp_sessions.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn shared_mcp_pool_uses_per_invocation_sessions() {
        let effects = Arc::new(Effects::default());
        let broker = broker(effects.clone());
        let binary = invocation_for("binary-hunt", mcp_grant(&["compile"]));
        let fuzz = invocation_for("agentic-fuzz", mcp_grant(&["compile"]));

        broker
            .mcp_call(&binary, mcp_request("binary-hunt", "compile"))
            .await
            .unwrap();
        broker
            .mcp_call(&fuzz, mcp_request("agentic-fuzz", "compile"))
            .await
            .unwrap();

        let sessions = effects.mcp_sessions.lock().await;
        assert_eq!(sessions.len(), 2);
        assert_ne!(sessions[0].invocation_id, sessions[1].invocation_id);
    }

    #[test]
    fn hanging_mcp_server_is_killed_at_the_stricter_call_deadline() {
        let temp = tempfile::tempdir().unwrap();
        let script = temp.path().join("hanging-mcp.mjs");
        fs::write(
            &script,
            "process.stdin.resume(); setInterval(() => {}, 1000);\n",
        )
        .unwrap();
        let mount = StdioMcpMount {
            alias: "hanging".to_string(),
            command: vec!["node".to_string(), script.display().to_string()],
            descriptor_hash: "sha256:unused".to_string(),
            tools: BTreeMap::new(),
            cwd: temp.path().to_path_buf(),
            timeout_ms: Some(5_000),
        };
        let session = McpSessionKey {
            alias: "hanging".to_string(),
            module_id: ModuleId("test-module".to_string()),
            module_digest: Digest("sha256:test".to_string()),
            run_id: RunId("run-test".to_string()),
            invocation_id: InvocationId("inv-test".to_string()),
        };
        let timeout = mcp_call_timeout(mount.timeout_ms, Some(100));
        let started = Instant::now();

        let error = McpStdioClient::spawn(&mount, &session, timeout)
            .err()
            .unwrap();

        assert_eq!(timeout, Duration::from_millis(100));
        assert_eq!(error, KwpError::Deadline);
        assert!(started.elapsed() < Duration::from_secs(2));
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

        broker
            .fuzz_run(&inv, fuzz_request(FuzzEngine::CargoFuzz))
            .await
            .unwrap();
        let error = broker
            .fuzz_run(&inv, fuzz_request(FuzzEngine::Libfuzzer))
            .await
            .unwrap_err();

        assert_eq!(error, KwpError::denied("fuzz.engine"));
        assert_eq!(effects.fuzz_requests.lock().await.len(), 1);
    }

    #[test]
    fn fuzz_project_root_dot_is_valid_but_escape_is_denied() {
        let tmp = tempfile::tempdir().unwrap();

        assert_eq!(
            resolve_fuzz_project_path(tmp.path(), ".").unwrap(),
            fs::canonicalize(tmp.path()).unwrap()
        );
        assert_eq!(
            validate_fuzz_project_path("../outside").unwrap_err(),
            KwpError::denied("fuzz.projectPath")
        );
    }

    #[test]
    fn fuzz_rejects_unenforced_sandbox_modes() {
        let mut request = fuzz_request(FuzzEngine::CargoFuzz);
        request.sandbox.network = true;
        assert_eq!(
            validate_fuzz_execution_request(&request).unwrap_err(),
            KwpError::denied("fuzz.network")
        );

        request.sandbox.network = false;
        request.sandbox.read_only_source = false;
        assert_eq!(
            validate_fuzz_execution_request(&request).unwrap_err(),
            KwpError::denied("fuzz.source_write")
        );

        request.sandbox.read_only_source = true;
        request.limits.memory_bytes = Some(1024);
        assert_eq!(
            validate_fuzz_execution_request(&request).unwrap_err(),
            KwpError::denied("fuzz.memory_limit")
        );
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
            limits: FuzzLimits {
                cpu_seconds: Some(10),
                artifact_bytes: Some(128),
                ..FuzzLimits::default()
            },
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

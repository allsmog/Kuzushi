//! Kuzushi Worker Protocol (KWP) v0.1 host primitives.
//!
//! This module implements the policy/data surface for out-of-process modules:
//! digest-pinned trust, immutable grants, invocation-scoped broker checks,
//! host-mediated MCP composition, fuzz execution delegation, audit records,
//! JSON-RPC message shapes, and supervisor/executor seams.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

pub const KWP_VERSION: &str = "0.1.0";
pub const METHOD_MCP_CALL: &str = "kuzushi/mcp/call";
pub const METHOD_FUZZ_RUN: &str = "kuzushi/fuzz/run";

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
    mcp_calls: u32,
    fuzz_jobs: u32,
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
}

#[derive(Clone, Debug)]
pub struct VerifiedModule {
    pub module_id: ModuleId,
    pub digest: Digest,
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
    #[error("resolver failed: {0}")]
    Resolver(String),
}

#[async_trait]
pub trait BundleResolver: Send + Sync {
    async fn resolve(&self, specifier: &str) -> Result<WorkerBundle, TrustError>;
}

pub trait SignatureVerifier: Send + Sync {
    fn verify_chain(&self, entry: &LockfileEntry, bundle: &WorkerBundle) -> bool;
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
        if !self.signatures.verify_chain(entry, &bundle) {
            return Err(TrustError::BadSignature);
        }
        Ok(VerifiedModule {
            module_id: bundle.module_id,
            digest: bundle.digest,
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
        inv.ensure_active()?;
        inv.ensure_epoch_current()?;
        inv.grant().fs_scope(scope).ok_or_else(|| KwpError::denied("fs"))?;
        validate_relative_path(path).map_err(|_| KwpError::denied("fs.path"))?;
        let result = self.fs.read(scope, path, 0, None).await;
        self.record(inv, "fs.read", &result).await;
        result
    }

    pub async fn fs_write(&self, inv: &InvocationAuthority, scope: FsScope, path: &str, data: Vec<u8>) -> Result<u64, KwpError> {
        inv.ensure_active()?;
        inv.ensure_epoch_current()?;
        if !inv.grant().allows_fs_write(scope) {
            return Err(KwpError::denied("fs.write"));
        }
        validate_relative_path(path).map_err(|_| KwpError::denied("fs.path"))?;
        let result = self.fs.write(scope, path, data, false).await;
        self.record(inv, "fs.write", &result).await;
        result
    }

    pub async fn net_fetch(&self, inv: &InvocationAuthority, request: NetFetchRequest) -> Result<NetFetchResult, KwpError> {
        inv.ensure_active()?;
        inv.ensure_epoch_current()?;
        let grant = inv.grant().net.as_ref().ok_or_else(|| KwpError::denied("net"))?;
        let (host, port) = parse_https_host_port(&request.url).ok_or_else(|| KwpError::denied("net.url"))?;
        if !grant.allow.iter().any(|pattern| pattern.matches(&host, port)) {
            return Err(KwpError::denied("net.host"));
        }
        let result = self.net.fetch(strip_untrusted_headers(request)).await;
        self.record(inv, "net.fetch", &result).await;
        result
    }

    pub async fn runtime_query(&self, inv: &InvocationAuthority, request: RuntimeQueryRequest) -> Result<RuntimeQueryResult, KwpError> {
        inv.ensure_active()?;
        inv.ensure_epoch_current()?;
        let grant = inv.grant().runtime.as_ref().ok_or_else(|| KwpError::denied("runtime"))?;
        if inv.computed_cost_usd().await >= grant.max_cost_usd_per_invocation {
            return Err(KwpError::RuntimeBudget);
        }
        let result = self.runtime.query(with_provenance(inv, request)).await;
        if let Ok(result) = &result {
            inv.add_runtime_cost(result.cost_usd).await;
        }
        self.record(inv, "runtime.query", &result).await;
        result
    }

    pub async fn bus_publish(&self, inv: &InvocationAuthority, topic: String, payload: Value) -> Result<(), KwpError> {
        inv.ensure_active()?;
        inv.ensure_epoch_current()?;
        if !inv.grant().bus.produce.iter().any(|pattern| pattern.matches(&topic)) {
            return Err(KwpError::denied("bus.produce"));
        }
        let result = self.bus.publish(origin(inv), topic, payload).await;
        self.record(inv, "bus.publish", &result).await;
        result
    }

    pub async fn findings_create(&self, inv: &InvocationAuthority, findings: Vec<Value>) -> Result<FindingsCreateResult, KwpError> {
        inv.ensure_active()?;
        inv.ensure_epoch_current()?;
        let grant = inv.grant().findings.as_ref().filter(|grant| grant.create).ok_or_else(|| KwpError::denied("findings.create"))?;
        if let Some(max) = grant.max_per_invocation {
            if findings.len() > max as usize {
                return Err(KwpError::quota("findings.count"));
            }
        }
        let result = self.findings.create(origin(inv), findings).await;
        self.record(inv, "findings.create", &result).await;
        result
    }

    pub async fn artifacts_record(&self, inv: &InvocationAuthority, artifacts: Vec<ArtifactRef>) -> Result<Vec<ArtifactRef>, KwpError> {
        inv.ensure_active()?;
        inv.ensure_epoch_current()?;
        inv.grant().artifacts.as_ref().filter(|grant| grant.write).ok_or_else(|| KwpError::denied("artifacts.write"))?;
        validate_artifact_refs(&artifacts)?;
        let result = self.artifacts.record(origin(inv), artifacts).await;
        self.record(inv, "artifacts.record", &result).await;
        result
    }

    pub async fn mcp_call(&self, inv: &InvocationAuthority, request: McpCallRequest) -> Result<McpCallResult, KwpError> {
        inv.ensure_active()?;
        inv.ensure_epoch_current()?;
        inv.ensure_invocation_id(&request.invocation_id)?;
        let grant = inv.grant().mcp_grant(&request.alias).ok_or_else(|| KwpError::denied("mcp"))?;
        if !grant.allows_tool(&request.tool) {
            return Err(KwpError::denied("mcp.tool"));
        }
        inv.reserve_mcp_call(grant, &request.limits).await?;
        let entry = self.mcp_catalog.get(&request.alias).ok_or_else(|| KwpError::denied("mcp.mount"))?;
        if !entry.tools.contains_key(&request.tool) {
            return Err(KwpError::denied("mcp.catalog.tool"));
        }
        let result = self.mcp.call(mcp_session(inv, &request.alias), request).await;
        if let Ok(result) = &result {
            validate_artifact_refs(&result.artifacts)?;
        }
        self.record(inv, "mcp.call", &result).await;
        result
    }

    pub async fn fuzz_run(&self, inv: &InvocationAuthority, request: FuzzRunRequest) -> Result<FuzzRunResult, KwpError> {
        inv.ensure_active()?;
        inv.ensure_epoch_current()?;
        inv.ensure_invocation_id(&request.invocation_id)?;
        let grant = inv.grant().fuzz.as_ref().ok_or_else(|| KwpError::denied("fuzz"))?;
        if !grant.allows_engine(request.engine) {
            return Err(KwpError::denied("fuzz.engine"));
        }
        if request.sandbox.network && !grant.network {
            return Err(KwpError::denied("fuzz.network"));
        }
        validate_relative_path(&request.target.project_path).map_err(|_| KwpError::denied("fuzz.projectPath"))?;
        validate_relative_path(&request.target.harness_path).map_err(|_| KwpError::denied("fuzz.harnessPath"))?;
        inv.reserve_fuzz_job(grant, &request).await?;
        let result = self.fuzz.run(origin(inv), request).await;
        if let Ok(result) = &result {
            validate_artifact_refs(&result.artifacts)?;
        }
        self.record(inv, "fuzz.run", &result).await;
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

fn parse_https_host_port(url: &str) -> Option<(String, u16)> {
    let rest = url.strip_prefix("https://")?;
    let host_port = rest.split('/').next()?;
    let (host, port) = host_port
        .rsplit_once(':')
        .map(|(host, port)| (host, port.parse::<u16>().ok()))
        .unwrap_or((host_port, Some(443)));
    Some((host.to_ascii_lowercase(), port?))
}

fn strip_untrusted_headers(mut request: NetFetchRequest) -> NetFetchRequest {
    request.headers.retain(|name, _| {
        let lower = name.to_ascii_lowercase();
        lower != "authorization" && lower != "cookie" && !lower.starts_with("proxy-") && !lower.starts_with("x-forwarded-")
    });
    request
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum RpcMessage {
    Request { id: u64, method: String, params: Value },
    Response { id: u64, result: Result<Value, RpcError> },
    Notification { method: String, params: Value },
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
    let mut bytes = serde_json::to_vec(message).map_err(|error| KwpError::Internal(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn decode_rpc_line(bytes: &[u8]) -> Result<RpcMessage, KwpError> {
    serde_json::from_slice(bytes).map_err(|error| KwpError::BadRequest(error.to_string()))
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

    #[tokio::test]
    async fn trust_verifier_pins_digest_to_lockfile_entry() {
        let bundle = WorkerBundle {
            specifier: "package:agentic-fuzz".to_string(),
            module_id: ModuleId("agentic-fuzz".to_string()),
            module_root: PathBuf::from("/tmp/module"),
            entry: "dist/index.js".to_string(),
            tier: ExecutorTier::Node,
            digest: Digest("sha256:abc".to_string()),
        };
        let mut lockfile = KuzushiLockfile::default();
        lockfile.modules.insert(
            "sha256:abc".to_string(),
            LockfileEntry {
                module_id: bundle.module_id.clone(),
                digest: bundle.digest.clone(),
                version: "1.0.0".to_string(),
                descriptor_hash: "sha256:descriptor".to_string(),
                grant: Grant::default(),
                signature_chain: Vec::new(),
                revoked: false,
            },
        );
        let verifier = LockfileTrustVerifier::new(Arc::new(lockfile), Arc::new(FixedResolver(bundle)), Arc::new(AllowSignatures));

        let verified = verifier.verify("package:agentic-fuzz").await.unwrap();

        assert_eq!(verified.digest, Digest("sha256:abc".to_string()));
        assert_eq!(verified.module_id, ModuleId("agentic-fuzz".to_string()));
    }

    #[tokio::test]
    async fn module_without_mcp_grant_cannot_call_mcp() {
        let effects = Arc::new(Effects::default());
        let broker = broker(effects.clone());
        let inv = invocation_for("agentic-fuzz", Grant::default());

        let error = broker.mcp_call(&inv, mcp_request("agentic-fuzz", "compile")).await.unwrap_err();

        assert_eq!(error, KwpError::denied("mcp"));
        assert!(effects.mcp_sessions.lock().await.is_empty());
        assert_eq!(effects.audit.lock().await[0].decision, AuditDecision::Deny);
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

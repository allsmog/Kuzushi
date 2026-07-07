//! Kuzushi Worker Protocol (KWP) domain primitives.
//!
//! This module is the first implementation slice for the KWP architecture:
//! content-addressed module authority, immutable grants, invocation-scoped
//! capability checks, and host-brokered MCP composition.
//!
//! The implementation intentionally keeps effect backends out of the policy
//! types. Backends execute already-authorized work; brokers enforce grants,
//! quotas, session isolation, and audit.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

pub const KWP_VERSION: &str = "0.1.0";
pub const METHOD_MCP_CALL: &str = "kuzushi/mcp/call";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ModuleId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Digest(pub String);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct InvocationId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RunId(pub String);

pub type Epoch = u64;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum KwpError {
    #[error("no active invocation")]
    NoActiveInvocation,
    #[error("capability not granted: {capability}")]
    NotGranted { capability: String },
    #[error("quota exceeded: {resource}")]
    QuotaExceeded { resource: String },
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
            Self::NotGranted { .. } => -32031,
            Self::QuotaExceeded { .. } => -32032,
            Self::RuntimeBudget => -32033,
            Self::EpochStale => -32034,
            Self::Deadline => -32035,
            Self::BadRequest(_) => -32602,
            Self::Internal(_) => -32603,
        }
    }

    pub fn denied(capability: impl Into<String>) -> Self {
        Self::NotGranted {
            capability: capability.into(),
        }
    }

    pub fn quota(resource: impl Into<String>) -> Self {
        Self::QuotaExceeded {
            resource: resource.into(),
        }
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
    epoch: Epoch,
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

    async fn reserve_mcp_call(&self, grant: &McpGrant, limits: &McpCallLimits) -> Result<(), KwpError> {
        let mut meter = self.meter.lock().await;
        meter.mcp_calls += 1;
        if let Some(max) = grant.max_calls_per_invocation {
            if meter.mcp_calls > max {
                return Err(KwpError::quota("mcp.calls"));
            }
        }
        if let (Some(limit), Some(max)) = (limits.cpu_seconds, grant.max_cpu_seconds_per_invocation) {
            if limit > max {
                return Err(KwpError::quota("mcp.cpu_seconds"));
            }
        }
        if let (Some(limit), Some(max)) = (limits.artifact_bytes, grant.max_artifacts_bytes_per_invocation) {
            if limit > max {
                return Err(KwpError::quota("mcp.artifact_bytes"));
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct InvocationMeter {
    mcp_calls: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct McpMount {
    pub alias: String,
    pub kind: McpMountKind,
    pub descriptor_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub tools: Vec<McpToolDescriptor>,
    pub default_isolation: McpIsolationPolicy,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum McpMountKind {
    Stdio,
    Container,
    Remote,
    Adapter,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum McpIsolationPolicy {
    SharedProcessIsolatedSession,
    DedicatedProcess,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct McpToolDescriptor {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct McpCatalogEntry {
    pub alias: String,
    pub descriptor_hash: String,
    pub tools: BTreeMap<String, McpToolDescriptor>,
    pub isolation: McpIsolationPolicy,
}

impl McpCatalogEntry {
    pub fn from_mount(mount: McpMount) -> Self {
        let tools = mount
            .tools
            .into_iter()
            .map(|tool| (tool.name.clone(), tool))
            .collect();
        Self {
            alias: mount.alias,
            descriptor_hash: mount.descriptor_hash,
            tools,
            isolation: mount.default_isolation,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactRef {
    pub path: String,
    pub media_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpCallResult {
    #[serde(default)]
    pub content: Vec<McpContent>,
    #[serde(default)]
    pub structured_content: Value,
    #[serde(default)]
    pub artifacts: Vec<ArtifactRef>,
}

impl Default for McpCallResult {
    fn default() -> Self {
        Self {
            content: Vec::new(),
            structured_content: Value::Null,
            artifacts: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct McpContent {
    #[serde(rename = "type")]
    pub content_type: String,
    pub text: String,
}

#[async_trait]
pub trait McpBackend: Send + Sync {
    async fn call(&self, session: McpSessionKey, request: McpCallRequest) -> Result<McpCallResult, KwpError>;
}

#[async_trait]
pub trait McpAuditSink: Send + Sync {
    async fn record(&self, record: McpAuditRecord);
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct McpAuditRecord {
    pub event: String,
    pub decision: AuditDecision,
    pub module_id: ModuleId,
    pub digest: Digest,
    pub invocation_id: InvocationId,
    pub alias: String,
    pub tool: String,
    pub detail: Value,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AuditDecision {
    Allow,
    Deny,
}

pub struct McpBroker {
    catalog: Arc<McpCatalog>,
    backend: Arc<dyn McpBackend>,
    audit: Arc<dyn McpAuditSink>,
}

impl McpBroker {
    pub fn new(catalog: Arc<McpCatalog>, backend: Arc<dyn McpBackend>, audit: Arc<dyn McpAuditSink>) -> Self {
        Self {
            catalog,
            backend,
            audit,
        }
    }

    pub async fn call(&self, inv: &InvocationAuthority, request: McpCallRequest) -> Result<McpCallResult, KwpError> {
        let outcome = self.call_checked(inv, request.clone()).await;
        self.audit
            .record(mcp_audit_record(inv, &request, &outcome))
            .await;
        outcome
    }

    async fn call_checked(&self, inv: &InvocationAuthority, request: McpCallRequest) -> Result<McpCallResult, KwpError> {
        inv.ensure_active()?;
        inv.ensure_epoch_current()?;
        if request.invocation_id != *inv.invocation_id() {
            return Err(KwpError::NoActiveInvocation);
        }

        let grant = inv
            .grant()
            .mcp_grant(&request.alias)
            .ok_or_else(|| KwpError::denied("mcp"))?;
        if !grant.allows_tool(&request.tool) {
            return Err(KwpError::denied("mcp.tool"));
        }
        inv.reserve_mcp_call(grant, &request.limits).await?;

        let entry = self
            .catalog
            .get(&request.alias)
            .ok_or_else(|| KwpError::denied("mcp.mount"))?;
        if !entry.tools.contains_key(&request.tool) {
            return Err(KwpError::denied("mcp.catalog.tool"));
        }

        let session = McpSessionKey {
            alias: request.alias.clone(),
            module_id: inv.module_id().clone(),
            module_digest: inv.digest().clone(),
            run_id: inv.run_id().clone(),
            invocation_id: inv.invocation_id().clone(),
        };
        let result = self.backend.call(session, request).await?;
        validate_artifact_refs(&result.artifacts)?;
        Ok(result)
    }
}

fn mcp_audit_record(
    inv: &InvocationAuthority,
    request: &McpCallRequest,
    outcome: &Result<McpCallResult, KwpError>,
) -> McpAuditRecord {
    let detail = match outcome {
        Ok(result) => serde_json::json!({
            "artifactCount": result.artifacts.len(),
        }),
        Err(error) => serde_json::json!({
            "errorCode": error.code(),
            "error": error.to_string(),
        }),
    };
    McpAuditRecord {
        event: "mcp.call".to_string(),
        decision: if outcome.is_ok() {
            AuditDecision::Allow
        } else {
            AuditDecision::Deny
        },
        module_id: inv.module_id().clone(),
        digest: inv.digest().clone(),
        invocation_id: inv.invocation_id().clone(),
        alias: request.alias.clone(),
        tool: request.tool.clone(),
        detail,
    }
}

pub fn validate_artifact_refs(artifacts: &[ArtifactRef]) -> Result<(), KwpError> {
    for artifact in artifacts {
        validate_relative_path(&artifact.path).map_err(|_| KwpError::denied("artifact.path"))?;
    }
    Ok(())
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathValidationError;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::sync::Mutex;

    #[derive(Default)]
    struct RecordingBackend {
        sessions: Mutex<Vec<McpSessionKey>>,
        result: Mutex<McpCallResult>,
    }

    #[async_trait]
    impl McpBackend for RecordingBackend {
        async fn call(&self, session: McpSessionKey, _request: McpCallRequest) -> Result<McpCallResult, KwpError> {
            self.sessions.lock().await.push(session);
            Ok(self.result.lock().await.clone())
        }
    }

    #[derive(Default)]
    struct RecordingAudit {
        records: Mutex<Vec<McpAuditRecord>>,
    }

    #[async_trait]
    impl McpAuditSink for RecordingAudit {
        async fn record(&self, record: McpAuditRecord) {
            self.records.lock().await.push(record);
        }
    }

    fn symcc_catalog() -> Arc<McpCatalog> {
        let mut catalog = McpCatalog::default();
        catalog.insert(McpCatalogEntry {
            alias: "symcc".to_string(),
            descriptor_hash: "sha256:descriptor".to_string(),
            isolation: McpIsolationPolicy::SharedProcessIsolatedSession,
            tools: BTreeMap::from([
                (
                    "compile".to_string(),
                    McpToolDescriptor {
                        name: "compile".to_string(),
                        description: "compile with SymCC".to_string(),
                        input_schema: json!({ "type": "object" }),
                        output_schema: None,
                    },
                ),
                (
                    "export_corpus".to_string(),
                    McpToolDescriptor {
                        name: "export_corpus".to_string(),
                        description: "export generated corpus".to_string(),
                        input_schema: json!({ "type": "object" }),
                        output_schema: None,
                    },
                ),
            ]),
        });
        Arc::new(catalog)
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

    fn mcp_request(module: &str, tool: &str) -> McpCallRequest {
        McpCallRequest {
            invocation_id: InvocationId(format!("inv_{module}")),
            alias: "symcc".to_string(),
            tool: tool.to_string(),
            arguments: json!({}),
            limits: McpCallLimits::default(),
        }
    }

    fn broker_with(backend: Arc<RecordingBackend>, audit: Arc<RecordingAudit>) -> McpBroker {
        McpBroker::new(symcc_catalog(), backend, audit)
    }

    #[tokio::test]
    async fn module_without_mcp_grant_cannot_call_mcp() {
        let backend = Arc::new(RecordingBackend::default());
        let audit = Arc::new(RecordingAudit::default());
        let broker = broker_with(backend.clone(), audit.clone());
        let inv = invocation_for("agentic-fuzz", Grant::default());

        let error = broker
            .call(&inv, mcp_request("agentic-fuzz", "compile"))
            .await
            .unwrap_err();

        assert_eq!(error, KwpError::denied("mcp"));
        assert!(backend.sessions.lock().await.is_empty());
        assert_eq!(audit.records.lock().await[0].decision, AuditDecision::Deny);
    }

    #[tokio::test]
    async fn grant_allows_only_listed_symcc_tools() {
        let backend = Arc::new(RecordingBackend::default());
        let audit = Arc::new(RecordingAudit::default());
        let broker = broker_with(backend.clone(), audit);
        let inv = invocation_for(
            "binary-hunt",
            Grant {
                mcp: vec![McpGrant {
                    alias: "symcc".to_string(),
                    tools: vec!["compile".to_string()],
                    mode: McpGrantMode::Shared,
                    max_calls_per_invocation: None,
                    max_cpu_seconds_per_invocation: None,
                    max_bytes_per_invocation: None,
                    max_artifacts_bytes_per_invocation: None,
                    workspace: McpWorkspaceMode::ScratchOnly,
                }],
                ..Grant::default()
            },
        );

        broker
            .call(&inv, mcp_request("binary-hunt", "compile"))
            .await
            .unwrap();
        let error = broker
            .call(&inv, mcp_request("binary-hunt", "export_corpus"))
            .await
            .unwrap_err();

        assert_eq!(error, KwpError::denied("mcp.tool"));
        assert_eq!(backend.sessions.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn shared_symcc_pool_uses_per_invocation_sessions() {
        let backend = Arc::new(RecordingBackend::default());
        let audit = Arc::new(RecordingAudit::default());
        let broker = broker_with(backend.clone(), audit);
        let grant = Grant {
            mcp: vec![McpGrant {
                alias: "symcc".to_string(),
                tools: vec!["compile".to_string()],
                mode: McpGrantMode::Shared,
                max_calls_per_invocation: None,
                max_cpu_seconds_per_invocation: None,
                max_bytes_per_invocation: None,
                max_artifacts_bytes_per_invocation: None,
                workspace: McpWorkspaceMode::ScratchOnly,
            }],
            ..Grant::default()
        };
        let binary = invocation_for("binary-hunt", grant.clone());
        let fuzz = invocation_for("agentic-fuzz", grant);

        broker
            .call(&binary, mcp_request("binary-hunt", "compile"))
            .await
            .unwrap();
        broker
            .call(&fuzz, mcp_request("agentic-fuzz", "compile"))
            .await
            .unwrap();

        let sessions = backend.sessions.lock().await;
        assert_eq!(sessions.len(), 2);
        assert_ne!(sessions[0].invocation_id, sessions[1].invocation_id);
        assert_eq!(sessions[0].alias, "symcc");
        assert_eq!(sessions[1].alias, "symcc");
    }

    #[tokio::test]
    async fn mcp_artifact_path_escape_is_rejected() {
        let backend = Arc::new(RecordingBackend::default());
        backend.result.lock().await.artifacts = vec![ArtifactRef {
            path: "../escape".to_string(),
            media_type: "text/plain".to_string(),
            sha256: None,
        }];
        let audit = Arc::new(RecordingAudit::default());
        let broker = broker_with(backend, audit);
        let inv = invocation_for(
            "agentic-fuzz",
            Grant {
                mcp: vec![McpGrant {
                    alias: "symcc".to_string(),
                    tools: vec!["compile".to_string()],
                    mode: McpGrantMode::Shared,
                    max_calls_per_invocation: None,
                    max_cpu_seconds_per_invocation: None,
                    max_bytes_per_invocation: None,
                    max_artifacts_bytes_per_invocation: None,
                    workspace: McpWorkspaceMode::ScratchOnly,
                }],
                ..Grant::default()
            },
        );

        let error = broker
            .call(&inv, mcp_request("agentic-fuzz", "compile"))
            .await
            .unwrap_err();

        assert_eq!(error, KwpError::denied("artifact.path"));
    }
}

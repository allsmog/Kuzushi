use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AttackSurfaceMap {
    pub root_name: String,
    pub surfaces: Vec<AttackSurface>,
    pub summary: AttackSurfaceSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AttackSurfaceSummary {
    pub total: usize,
    pub by_kind: BTreeMap<String, usize>,
    pub by_file: BTreeMap<String, usize>,
    #[serde(default)]
    pub high_risk: usize,
    #[serde(default)]
    pub max_risk_score: u16,
    #[serde(default)]
    pub by_risk_tier: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AttackSurfaceKind {
    HttpRoute,
    RpcHandler,
    CliEntrypoint,
    BackgroundJob,
    DeserializationPoint,
    FileUploadParsePath,
    ExternalServiceClient,
    AuthBoundary,
    SessionStateBoundary,
    RequestTrustBoundary,
    TenantIsolationBoundary,
    DbQueryBoundary,
    CommandExecutionBoundary,
}

impl AttackSurfaceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HttpRoute => "http_route",
            Self::RpcHandler => "rpc_handler",
            Self::CliEntrypoint => "cli_entrypoint",
            Self::BackgroundJob => "background_job",
            Self::DeserializationPoint => "deserialization_point",
            Self::FileUploadParsePath => "file_upload_parse_path",
            Self::ExternalServiceClient => "external_service_client",
            Self::AuthBoundary => "auth_boundary",
            Self::SessionStateBoundary => "session_state_boundary",
            Self::RequestTrustBoundary => "request_trust_boundary",
            Self::TenantIsolationBoundary => "tenant_isolation_boundary",
            Self::DbQueryBoundary => "db_query_boundary",
            Self::CommandExecutionBoundary => "command_execution_boundary",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AttackSurface {
    pub id: String,
    pub kind: AttackSurfaceKind,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    pub language: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
    pub title: String,
    pub evidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boundary: Option<String>,
    #[serde(default)]
    pub risk: AttackSurfaceRisk,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AttackSurfaceRisk {
    pub rank: usize,
    pub score: u16,
    pub tier: String,
    pub reasons: Vec<String>,
}

impl Default for AttackSurfaceRisk {
    fn default() -> Self {
        Self {
            rank: 0,
            score: 0,
            tier: "low".to_string(),
            reasons: Vec::new(),
        }
    }
}

impl AttackSurface {
    pub(crate) fn from_draft(draft: AttackSurfaceDraft) -> Self {
        let mut surface = Self {
            id: String::new(),
            kind: draft.kind,
            path: draft.path,
            line: draft.line,
            language: draft.language,
            framework: draft.framework,
            title: draft.title,
            evidence: draft.evidence,
            method: draft.method,
            route: draft.route,
            boundary: draft.boundary,
            risk: AttackSurfaceRisk::default(),
            metadata: draft.metadata,
        };
        surface.id = attack_surface_id(&surface);
        surface
    }
}

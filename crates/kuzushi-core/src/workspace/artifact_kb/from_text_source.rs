use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactKnowledgeRecord {
    pub id: String,
    pub source_path: String,
    pub module_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub content_hash: String,
    pub title: String,
    pub summary: String,
    pub body: String,
    #[serde(default)]
    pub refs: Vec<String>,
    #[serde(default)]
    pub metadata: Value,
    pub indexed_at_unix: u64,
}

impl ArtifactKnowledgeRecord {
    pub fn from_text_source(
        workspace: &WorkspaceTarget,
        source_path: impl Into<String>,
        module_id: impl Into<String>,
        run_id: Option<String>,
        title: impl Into<String>,
        refs: Vec<String>,
        metadata: Value,
    ) -> Result<Self> {
        let source_path = source_path.into();
        let absolute = workspace.root().join(&source_path);
        let bytes = fs::read(&absolute)
            .with_context(|| format!("Could not read artifact {}", absolute.display()))?;
        let body = String::from_utf8(bytes.clone())
            .with_context(|| format!("Artifact {} is not UTF-8 text", absolute.display()))?;
        let module_id = module_id.into();
        let title = title.into();
        let id = artifact_record_id(&module_id, &source_path, run_id.as_deref(), &title);
        Ok(Self {
            id,
            source_path,
            module_id,
            run_id,
            content_hash: fnv1a_hex(&bytes),
            title,
            summary: summarize_body(&body),
            body,
            refs,
            metadata,
            indexed_at_unix: now_unix(),
        })
    }

    pub fn from_body(
        source_path: impl Into<String>,
        module_id: impl Into<String>,
        run_id: Option<String>,
        title: impl Into<String>,
        body: impl Into<String>,
        refs: Vec<String>,
        metadata: Value,
    ) -> Self {
        let source_path = source_path.into();
        let module_id = module_id.into();
        let title = title.into();
        let body = body.into();
        let id = artifact_record_id(&module_id, &source_path, run_id.as_deref(), &title);
        Self {
            id,
            source_path,
            module_id,
            run_id,
            content_hash: fnv1a_hex(body.as_bytes()),
            summary: summarize_body(&body),
            body,
            title,
            refs,
            metadata,
            indexed_at_unix: now_unix(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactSearchResult {
    pub record: ArtifactKnowledgeRecord,
    pub score: f64,
    pub snippet: String,
}

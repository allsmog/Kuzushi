use super::*;

pub fn search_artifact_knowledge(
    workspace: &WorkspaceTarget,
    query: &str,
    limit: usize,
) -> Result<ArtifactSearchReport> {
    let db_path = artifact_kb_path(workspace);
    if !db_path.exists() {
        return Ok(ArtifactSearchReport {
            db_path: db_path.display().to_string(),
            missing_db: true,
            query: query.to_string(),
            results: Vec::new(),
        });
    }
    let store = ArtifactKnowledgeStore::open_path(&db_path)?;
    let results = store.search(query, limit)?;
    Ok(ArtifactSearchReport {
        db_path: db_path.display().to_string(),
        missing_db: false,
        query: query.to_string(),
        results,
    })
}

pub fn artifact_knowledge_prompt_context(
    workspace: &WorkspaceTarget,
    query: &str,
    limit: usize,
) -> ArtifactKnowledgePromptContext {
    let db_path = artifact_kb_path(workspace).display().to_string();
    match build_prompt_context(workspace, query, limit) {
        Ok(context) => context,
        Err(error) => ArtifactKnowledgePromptContext {
            db_path,
            missing_db: false,
            query: query.to_string(),
            status: format!("unavailable: {error}"),
            snippets: Vec::new(),
        },
    }
}

fn build_prompt_context(
    workspace: &WorkspaceTarget,
    query: &str,
    limit: usize,
) -> Result<ArtifactKnowledgePromptContext> {
    let db_path = artifact_kb_path(workspace);
    if !db_path.exists() {
        let db_path = db_path.display().to_string();
        return Ok(ArtifactKnowledgePromptContext {
            status: missing_prompt_context_status(&db_path),
            db_path,
            missing_db: true,
            query: query.to_string(),
            snippets: Vec::new(),
        });
    }
    let store = ArtifactKnowledgeStore::open_path(&db_path)?;
    let snippets = store.search_prompt_snippets(query, limit)?;
    Ok(ArtifactKnowledgePromptContext {
        status: available_prompt_context_status(snippets.len()),
        db_path: db_path.display().to_string(),
        missing_db: false,
        query: query.to_string(),
        snippets,
    })
}

fn missing_prompt_context_status(db_path: &str) -> String {
    format!(
        "missing local artifact KB at {db_path}; run context:build or reparse attachments before expecting KB recall"
    )
}

fn available_prompt_context_status(snippet_count: usize) -> String {
    if snippet_count == 0 {
        return "available, no matching local artifact snippets".to_string();
    }
    format!("available, {snippet_count} matching snippet(s)")
}

pub struct ArtifactKnowledgeStore {
    pub(crate) conn: Connection,
    pub(crate) db_path: String,
}

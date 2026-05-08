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
    match search_artifact_knowledge(workspace, query, limit) {
        Ok(report) => {
            let snippets = report
                .results
                .into_iter()
                .map(|result| ArtifactKnowledgeSnippet {
                    source_path: result.record.source_path,
                    module_id: result.record.module_id,
                    run_id: result.record.run_id,
                    title: result.record.title,
                    summary: result.record.summary,
                    snippet: if result.snippet.trim().is_empty() {
                        summarize_body(&result.record.body)
                    } else {
                        result.snippet
                    },
                    refs: result.record.refs,
                })
                .collect::<Vec<_>>();
            let status = if report.missing_db {
                format!(
                    "missing local artifact KB at {}; run context:build or reparse attachments before expecting KB recall",
                    report.db_path
                )
            } else if snippets.is_empty() {
                "available, no matching local artifact snippets".to_string()
            } else {
                format!("available, {} matching snippet(s)", snippets.len())
            };
            ArtifactKnowledgePromptContext {
                db_path: report.db_path,
                missing_db: report.missing_db,
                query: report.query,
                status,
                snippets,
            }
        }
        Err(error) => ArtifactKnowledgePromptContext {
            db_path,
            missing_db: false,
            query: query.to_string(),
            status: format!("unavailable: {error}"),
            snippets: Vec::new(),
        },
    }
}

pub struct ArtifactKnowledgeStore {
    pub(crate) conn: Connection,
    pub(crate) db_path: String,
}

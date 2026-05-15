use super::compact_target_path;
use crate::ShellApp;
use kuzushi_core::{AttachmentKind, AttachmentRecord, KnownArtifact, SUPPORTED_ATTACHMENT_MODULES};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KnowledgeBaseModel {
    pub(crate) module_id_label: String,
    pub(crate) store_label: String,
    pub(crate) supported_label: String,
    pub(crate) artifact_rows: Vec<KnowledgeBaseArtifactRow>,
    pub(crate) attachment_rows: Vec<KnowledgeBaseAttachmentRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KnowledgeBaseArtifactRow {
    pub(crate) state: &'static str,
    pub(crate) path: String,
    pub(crate) description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KnowledgeBaseAttachmentRow {
    pub(crate) id: String,
    pub(crate) kind: &'static str,
    pub(crate) source: String,
    pub(crate) status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainKnowledgeBaseModel {
    pub(crate) title: &'static str,
    pub(crate) summary_rows: Vec<String>,
    pub(crate) artifact_section: PlainKnowledgeBaseArtifacts,
    pub(crate) attachment_section: PlainKnowledgeBaseAttachments,
    pub(crate) next_hint: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainKnowledgeBaseArtifacts {
    pub(crate) title: &'static str,
    pub(crate) headers: [&'static str; 3],
    pub(crate) rows: Vec<PlainKnowledgeBaseArtifactRow>,
    pub(crate) empty_message: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainKnowledgeBaseArtifactRow {
    pub(crate) state: &'static str,
    pub(crate) path: String,
    pub(crate) description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainKnowledgeBaseAttachments {
    pub(crate) title: &'static str,
    pub(crate) headers: [&'static str; 4],
    pub(crate) rows: Vec<PlainKnowledgeBaseAttachmentRow>,
    pub(crate) empty_message: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainKnowledgeBaseAttachmentRow {
    pub(crate) id: String,
    pub(crate) kind: &'static str,
    pub(crate) source: String,
    pub(crate) status: String,
}

pub(crate) fn knowledge_base_model(app: &ShellApp) -> KnowledgeBaseModel {
    let view = &app.kb_view;
    KnowledgeBaseModel {
        module_id_label: view.module_id.clone(),
        store_label: store_label(view.store_path.as_ref()),
        supported_label: SUPPORTED_ATTACHMENT_MODULES.join(", "),
        artifact_rows: artifact_rows(&view.artifacts),
        attachment_rows: attachment_rows(&view.attachments, &view.module_id),
    }
}

pub(crate) fn plain_knowledge_base_model(app: &ShellApp) -> PlainKnowledgeBaseModel {
    PlainKnowledgeBaseModel::from_knowledge_base_model(knowledge_base_model(app))
}

impl PlainKnowledgeBaseModel {
    fn from_knowledge_base_model(model: KnowledgeBaseModel) -> Self {
        PlainKnowledgeBaseModel {
            title: "KB ATTACHMENTS",
            summary_rows: vec![
                format!("module: {}", model.module_id_label),
                format!("store: {}", model.store_label),
                format!("supported: {}", model.supported_label),
            ],
            artifact_section: plain_artifacts(model.artifact_rows),
            attachment_section: plain_attachments(model.attachment_rows),
            next_hint: "Next: kb [module], attach <path-or-url>, detach <id>, reparse <id>",
        }
    }
}

fn plain_artifacts(rows: Vec<KnowledgeBaseArtifactRow>) -> PlainKnowledgeBaseArtifacts {
    PlainKnowledgeBaseArtifacts {
        title: "KNOWN ARTIFACTS",
        headers: ["state", "path", "description"],
        empty_message: rows
            .is_empty()
            .then_some("No known Rust artifacts for this module."),
        rows: rows.into_iter().map(plain_artifact_row).collect(),
    }
}

fn plain_artifact_row(row: KnowledgeBaseArtifactRow) -> PlainKnowledgeBaseArtifactRow {
    PlainKnowledgeBaseArtifactRow {
        state: row.state,
        path: row.path,
        description: row.description,
    }
}

fn plain_attachments(rows: Vec<KnowledgeBaseAttachmentRow>) -> PlainKnowledgeBaseAttachments {
    PlainKnowledgeBaseAttachments {
        title: "ATTACHED",
        headers: ["id", "kind", "source", "status"],
        empty_message: rows
            .is_empty()
            .then_some("No attachments yet. Next: attach <repo-relative-path> or attach <url>"),
        rows: rows.into_iter().map(plain_attachment_row).collect(),
    }
}

fn plain_attachment_row(row: KnowledgeBaseAttachmentRow) -> PlainKnowledgeBaseAttachmentRow {
    PlainKnowledgeBaseAttachmentRow {
        id: row.id,
        kind: row.kind,
        source: row.source,
        status: row.status,
    }
}

fn store_label(path: Option<&std::path::PathBuf>) -> String {
    path.map(|path| compact_target_path(&path.display().to_string()))
        .unwrap_or_else(|| ".kuzushi/v2/attachments.json".to_string())
}

fn artifact_rows(artifacts: &[KnownArtifact]) -> Vec<KnowledgeBaseArtifactRow> {
    artifacts
        .iter()
        .map(|artifact| KnowledgeBaseArtifactRow {
            state: if artifact.exists {
                "present"
            } else {
                "missing"
            },
            path: artifact.path.clone(),
            description: artifact.description.clone(),
        })
        .collect()
}

fn attachment_rows(
    records: &[AttachmentRecord],
    module_id: &str,
) -> Vec<KnowledgeBaseAttachmentRow> {
    records
        .iter()
        .filter(|record| record.module_id == module_id)
        .map(|record| KnowledgeBaseAttachmentRow {
            id: record.id.clone(),
            kind: attachment_kind(&record.kind),
            source: record.source.clone(),
            status: record.status.clone(),
        })
        .collect()
}

fn attachment_kind(kind: &AttachmentKind) -> &'static str {
    match kind {
        AttachmentKind::Path => "path",
        AttachmentKind::Url => "url",
    }
}

#[cfg(test)]
mod tests;

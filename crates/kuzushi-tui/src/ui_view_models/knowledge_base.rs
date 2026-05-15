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

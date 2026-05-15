use super::compact_target_path;
use crate::ShellApp;
use kuzushi_core::{AttachmentKind, AttachmentRecord, KnownArtifact, SUPPORTED_ATTACHMENT_MODULES};

const KB_SUMMARY_COLUMN_COUNT: usize = 2;
const KB_ARTIFACT_COLUMN_COUNT: usize = 3;
const KB_ATTACHMENT_COLUMN_COUNT: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KnowledgeBaseModel {
    pub(crate) title: &'static str,
    pub(crate) summary_rows: Vec<KnowledgeBaseSummaryRow>,
    pub(crate) artifact_rows: Vec<KnowledgeBaseArtifactRow>,
    pub(crate) attachment_rows: Vec<KnowledgeBaseAttachmentRow>,
    pub(crate) commands: [&'static str; 4],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KnowledgeBaseSummaryRow {
    pub(crate) cells: [String; KB_SUMMARY_COLUMN_COUNT],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KnowledgeBaseArtifactRow {
    pub(crate) cells: [String; KB_ARTIFACT_COLUMN_COUNT],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KnowledgeBaseAttachmentRow {
    pub(crate) cells: [String; KB_ATTACHMENT_COLUMN_COUNT],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainKnowledgeBaseModel {
    pub(crate) title: &'static str,
    pub(crate) summary_rows: Vec<String>,
    pub(crate) artifact_section: PlainKnowledgeBaseArtifacts,
    pub(crate) attachment_section: PlainKnowledgeBaseAttachments,
    pub(crate) next_hint: String,
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
    pub(crate) cells: [String; KB_ARTIFACT_COLUMN_COUNT],
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
    pub(crate) cells: [String; KB_ATTACHMENT_COLUMN_COUNT],
}

pub(crate) fn knowledge_base_model(app: &ShellApp) -> KnowledgeBaseModel {
    let view = &app.kb_view;
    let module_id_label = view.module_id.clone();
    let store_label = store_label(view.store_path.as_ref());
    let supported_label = SUPPORTED_ATTACHMENT_MODULES.join(", ");
    KnowledgeBaseModel {
        title: "KB ATTACHMENTS",
        summary_rows: summary_rows(&module_id_label, &store_label, &supported_label),
        artifact_rows: artifact_rows(&view.artifacts),
        attachment_rows: attachment_rows(&view.attachments, &view.module_id),
        commands: [
            "kb [module]",
            "attach <path-or-url>",
            "detach <id>",
            "reparse <id>",
        ],
    }
}

pub(crate) fn plain_knowledge_base_model(app: &ShellApp) -> PlainKnowledgeBaseModel {
    PlainKnowledgeBaseModel::from_knowledge_base_model(knowledge_base_model(app))
}

impl PlainKnowledgeBaseModel {
    fn from_knowledge_base_model(model: KnowledgeBaseModel) -> Self {
        let KnowledgeBaseModel {
            title,
            summary_rows,
            artifact_rows,
            attachment_rows,
            commands,
        } = model;
        PlainKnowledgeBaseModel {
            title,
            summary_rows: summary_rows.into_iter().map(plain_summary_row).collect(),
            artifact_section: plain_artifacts(artifact_rows),
            attachment_section: plain_attachments(attachment_rows),
            next_hint: format!("Next: {}", commands.join(", ")),
        }
    }
}

fn summary_rows(
    module_id_label: &str,
    store_label: &str,
    supported_label: &str,
) -> Vec<KnowledgeBaseSummaryRow> {
    vec![
        summary_row("module", module_id_label),
        summary_row("store", store_label),
        summary_row("supported", supported_label),
    ]
}

fn summary_row(label: &'static str, value: &str) -> KnowledgeBaseSummaryRow {
    KnowledgeBaseSummaryRow {
        cells: [label.to_string(), value.to_string()],
    }
}

fn plain_summary_row(row: KnowledgeBaseSummaryRow) -> String {
    let [label, value] = row.cells;
    format!("{label}: {value}")
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
    PlainKnowledgeBaseArtifactRow { cells: row.cells }
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
    PlainKnowledgeBaseAttachmentRow { cells: row.cells }
}

fn store_label(path: Option<&std::path::PathBuf>) -> String {
    path.map(|path| compact_target_path(&path.display().to_string()))
        .unwrap_or_else(|| ".kuzushi/v2/attachments.json".to_string())
}

fn artifact_rows(artifacts: &[KnownArtifact]) -> Vec<KnowledgeBaseArtifactRow> {
    artifacts
        .iter()
        .map(|artifact| KnowledgeBaseArtifactRow {
            cells: [
                if artifact.exists {
                    "present"
                } else {
                    "missing"
                }
                .to_string(),
                artifact.path.clone(),
                artifact.description.clone(),
            ],
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
            cells: [
                record.id.clone(),
                attachment_kind(&record.kind).to_string(),
                record.source.clone(),
                record.status.clone(),
            ],
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

use crate::app::FieldEditor;
use kuzushi_core::capabilities::threat_model::{
    context_text_fields, ContextTextEdit, MAX_CONTEXT_EDITS,
};
use kuzushi_core::ThreatModelRef;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContextEditMode {
    Fields,
    Writing,
    Review,
    Saving,
    Discard,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ContextEditEntry {
    pub pointer: Option<String>,
    pub label: String,
    pub original: String,
    pub editor: Option<FieldEditor>,
}

impl ContextEditEntry {
    pub fn text(&self) -> &str {
        self.editor
            .as_ref()
            .map_or(&self.original, FieldEditor::text)
    }
    pub fn changed(&self) -> bool {
        self.text() != self.original
    }
    pub fn begin_edit(&mut self) {
        self.editor
            .get_or_insert_with(|| FieldEditor::new(&self.original));
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ContextEditDraft {
    pub reference: ThreatModelRef,
    pub entries: Vec<ContextEditEntry>,
    pub cursor: usize,
    pub scroll: usize,
    pub mode: ContextEditMode,
    pub notice: Option<String>,
}

impl ContextEditDraft {
    pub fn new(reference: ThreatModelRef, document: &Value, label: String) -> Self {
        let mut entries = vec![ContextEditEntry {
            pointer: None,
            label: "Copy name".into(),
            original: label,
            editor: None,
        }];
        entries.extend(
            context_text_fields(document)
                .into_iter()
                .map(|field| ContextEditEntry {
                    pointer: Some(field.pointer),
                    label: field.label,
                    original: field.text,
                    editor: None,
                }),
        );
        Self {
            reference,
            entries,
            cursor: 1,
            scroll: 0,
            mode: ContextEditMode::Fields,
            notice: None,
        }
    }

    pub fn edits(&self) -> Vec<ContextTextEdit> {
        self.entries
            .iter()
            .filter(|entry| entry.changed())
            .filter_map(|entry| {
                entry.pointer.as_ref().map(|pointer| ContextTextEdit {
                    pointer: pointer.clone(),
                    text: entry.text().into(),
                })
            })
            .collect()
    }

    pub fn validate(&self) -> anyhow::Result<Vec<ContextTextEdit>> {
        let edits = self.edits();
        anyhow::ensure!(
            !edits.is_empty(),
            "Edit context text before reviewing a copy."
        );
        anyhow::ensure!(
            edits.len() <= MAX_CONTEXT_EDITS,
            "Review at most {MAX_CONTEXT_EDITS} text fields per copy."
        );
        let label = self.entries[0].text().trim();
        anyhow::ensure!(
            !label.is_empty() && label.len() <= 2048,
            "Copy name must contain 1 to 2048 bytes."
        );
        Ok(edits)
    }
}

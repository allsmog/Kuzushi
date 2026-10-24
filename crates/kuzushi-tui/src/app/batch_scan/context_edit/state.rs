use crate::app::FieldEditor;
use kuzushi_core::capabilities::threat_model::{
    context_operator_fields, ContextEditConstraint, ContextTextEdit, MAX_CONTEXT_EDITS,
};
use kuzushi_core::ThreatModelRef;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContextEditMode {
    Recovery,
    Fields,
    Writing,
    Choosing,
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
    pub constraint: ContextEditConstraint,
    pub regeneratable: bool,
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
    pub recovery: ContextDraftRecovery,
    pub checkpoint_origins: Vec<String>,
    pub choice_cursor: usize,
    pub choice_details: bool,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) enum ContextDraftRecovery {
    #[default]
    None,
    Loading,
    Choices {
        drafts: Vec<kuzushi_core::session_transcript::RecoveredContextDraft>,
        cursor: usize,
    },
    Failed(String),
}

impl ContextEditDraft {
    pub fn new(reference: ThreatModelRef, document: &Value, label: String) -> Self {
        let mut entries = vec![ContextEditEntry {
            pointer: None,
            label: "Copy name".into(),
            original: label,
            editor: None,
            constraint: ContextEditConstraint::Text,
            regeneratable: false,
        }];
        entries.extend(context_operator_fields(document).into_iter().map(|field| {
            ContextEditEntry {
                pointer: Some(field.text.pointer),
                label: field.text.label,
                original: field.text.text,
                editor: None,
                constraint: field.constraint,
                regeneratable: field.regeneratable,
            }
        }));
        Self {
            reference,
            entries,
            cursor: 1,
            scroll: 0,
            mode: ContextEditMode::Fields,
            notice: None,
            recovery: Default::default(),
            checkpoint_origins: Vec::new(),
            choice_cursor: 0,
            choice_details: false,
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
            "Edit a context field before reviewing a copy."
        );
        anyhow::ensure!(
            edits.len() <= MAX_CONTEXT_EDITS,
            "Review at most {MAX_CONTEXT_EDITS} fields per copy."
        );
        let label = self.entries[0].text().trim();
        anyhow::ensure!(
            !label.is_empty() && label.len() <= 2048,
            "Copy name must contain 1 to 2048 bytes."
        );
        self.validate_changed_values()?;
        Ok(edits)
    }

    fn validate_changed_values(&self) -> anyhow::Result<()> {
        for entry in self.entries.iter().filter(|entry| entry.changed()) {
            entry
                .constraint
                .validate(entry.text())
                .map_err(|error| anyhow::anyhow!("{error}. Field: {}", entry.label))?;
        }
        Ok(())
    }
}

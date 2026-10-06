use super::*;
use crate::app::FieldEditor;
use anyhow::{Context, Result};
use kuzushi_core::workspace::{ProposedScanScope, ScanScopeEdit};

impl ScopeEditForm {
    pub(super) fn for_scope(kind: ScopeEditKind, scope: &ProposedScanScope) -> Self {
        let fields = scope_fields(kind, scope);
        Self {
            omit_context: false,
            kind,
            template: scope.clone(),
            child_id_prefix: kuzushi_core::new_run_id("scope"),
            fields: fields
                .into_iter()
                .map(|(name, text)| (name, FieldEditor::new(text)))
                .collect(),
            cursor: 0,
        }
    }

    pub(super) fn enter_submits(&self) -> bool {
        self.fields.len() == 1 && self.kind != ScopeEditKind::AiPriorities
    }
}

fn scope_fields(kind: ScopeEditKind, scope: &ProposedScanScope) -> Vec<(&'static str, String)> {
    match kind {
        ScopeEditKind::AiPriorities => vec![(
            "Scope priorities (optional, at most 2048 bytes)",
            String::new(),
        )],
        ScopeEditKind::Rename => vec![("Name", scope.name.clone())],
        ScopeEditKind::Split => vec![
            ("First scope name", String::new()),
            ("First scope paths (one per line)", String::new()),
            ("Second scope name", String::new()),
            ("Second scope paths (one per line)", String::new()),
        ],
        ScopeEditKind::Exclude => vec![("Reason for excluding this scope", String::new())],
        ScopeEditKind::ExcludePath => vec![
            ("File or directory path", String::new()),
            ("Reason for exclusion", String::new()),
        ],
        ScopeEditKind::Boundary => vec![
            ("Boundary rationale", scope.rationale.clone()),
            (
                "Shared dependency ids (one per line)",
                scope.shared_dependencies.join("\n"),
            ),
            (
                "Open questions (one per line)",
                scope.open_questions.join("\n"),
            ),
        ],
    }
}

impl ScopeEditForm {
    pub(super) fn edit(&self, revision: u32) -> Result<ScanScopeEdit> {
        let id = self.template.id.clone();
        Ok(match self.kind {
            ScopeEditKind::AiPriorities => {
                anyhow::bail!("scope priorities prepare a model plan, never a boundary edit")
            }
            ScopeEditKind::Rename => ScanScopeEdit::Rename {
                scope_id: id,
                name: self.text(0)?,
            },
            ScopeEditKind::Exclude => ScanScopeEdit::Exclude {
                scope_id: id,
                reason: self.text(0)?,
            },
            ScopeEditKind::ExcludePath => ScanScopeEdit::ExcludePath {
                path: self.text(0)?,
                reason: self.text(1)?,
            },
            ScopeEditKind::Split => ScanScopeEdit::Split {
                scope_id: id,
                children: vec![self.child(0, revision)?, self.child(2, revision)?],
            },
            ScopeEditKind::Boundary => ScanScopeEdit::EditBoundary {
                scope_id: id,
                rationale: self.text(0)?,
                shared_dependencies: self.lines(1),
                open_questions: self.lines(2),
            },
        })
    }

    fn text(&self, index: usize) -> Result<String> {
        let text = self
            .fields
            .get(index)
            .context("Missing scope field")?
            .1
            .text()
            .trim();
        anyhow::ensure!(!text.is_empty(), "Fill in {}.", self.fields[index].0);
        Ok(text.into())
    }

    fn lines(&self, index: usize) -> Vec<String> {
        self.fields[index]
            .1
            .text()
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect()
    }

    fn child(&self, offset: usize, revision: u32) -> Result<ProposedScanScope> {
        let mut child = self.template.clone();
        child.id = format!("{}-r{revision}-{}", self.child_id_prefix, offset / 2 + 1);
        child.name = self.text(offset)?;
        child.paths = self.lines(offset + 1);
        child.rationale = format!(
            "Operator split {} into this boundary. Inherited rationale: {}",
            self.template.name, self.template.rationale
        );
        Ok(child)
    }
}

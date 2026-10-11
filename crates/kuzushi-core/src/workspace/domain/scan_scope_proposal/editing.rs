use super::*;
mod merge;
mod split;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "action",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ScanScopeEdit {
    Rename {
        scope_id: String,
        name: String,
    },
    Merge {
        from_scope: String,
        into_scope: String,
    },
    Split {
        scope_id: String,
        children: Vec<ProposedScanScope>,
    },
    Exclude {
        scope_id: String,
        reason: String,
    },
    ExcludePath {
        path: String,
        reason: String,
    },
    IncludePath {
        path: String,
    },
    EditBoundary {
        scope_id: String,
        rationale: String,
        shared_dependencies: Vec<String>,
        open_questions: Vec<String>,
    },
    SetSharedDiscovery {
        enabled: bool,
    },
    WholeRepository,
}

impl ScanScopeDraft {
    /// An invalid edit leaves the original draft intact. No edit starts work.
    pub fn edited(
        &self,
        edit: ScanScopeEdit,
        inventory: &RepositoryInventory,
    ) -> Result<(Self, ScanScopeCoverage)> {
        self.evaluate(inventory)?;
        let mut draft = self.clone();
        draft.apply_edit(edit, inventory)?;
        let coverage = draft.evaluate(inventory)?;
        Ok((draft, coverage))
    }

    fn apply_edit(&mut self, edit: ScanScopeEdit, inventory: &RepositoryInventory) -> Result<()> {
        match edit {
            ScanScopeEdit::Merge {
                from_scope,
                into_scope,
            } => merge::apply(self, &from_scope, &into_scope),
            ScanScopeEdit::Split { scope_id, children } => {
                split::apply(self, &scope_id, children, inventory)
            }
            other => self.apply_boundary_or_selection_edit(other),
        }
    }

    fn apply_boundary_or_selection_edit(&mut self, edit: ScanScopeEdit) -> Result<()> {
        match edit {
            ScanScopeEdit::Rename { scope_id, name } => self.selected_mut(&scope_id)?.name = name,
            ScanScopeEdit::EditBoundary {
                scope_id,
                rationale,
                shared_dependencies,
                open_questions,
            } => {
                let scope = self.selected_mut(&scope_id)?;
                scope.rationale = rationale;
                scope.shared_dependencies = shared_dependencies;
                scope.open_questions = open_questions;
            }
            other => return self.apply_selection_edit(other),
        }
        Ok(())
    }

    fn apply_selection_edit(&mut self, edit: ScanScopeEdit) -> Result<()> {
        match edit {
            ScanScopeEdit::Exclude { scope_id, reason } => self.exclude_scope(&scope_id, &reason),
            ScanScopeEdit::ExcludePath { path, reason } => {
                self.set_exclusion(path, &reason);
                Ok(())
            }
            ScanScopeEdit::IncludePath { path } => self.remove_exclusion(&path),
            ScanScopeEdit::SetSharedDiscovery { enabled } => {
                self.shared_discovery = enabled;
                Ok(())
            }
            ScanScopeEdit::WholeRepository => {
                self.select_whole_repository();
                Ok(())
            }
            _ => anyhow::bail!("unsupported scope selection edit"),
        }
    }

    fn selected_mut(&mut self, id: &str) -> Result<&mut ProposedScanScope> {
        self.scopes
            .iter_mut()
            .chain(self.shared_scope.iter_mut())
            .find(|scope| scope.id == id)
            .with_context(|| format!("scope {id:?} is not in this draft"))
    }

    fn exclude_scope(&mut self, id: &str, reason: &str) -> Result<()> {
        let paths = self.selected_mut(id)?.paths.clone();
        for path in paths {
            self.set_exclusion(path, reason);
        }
        Ok(())
    }

    fn set_exclusion(&mut self, path: String, reason: &str) {
        if let Some(exclusion) = self
            .exclusions
            .iter_mut()
            .find(|exclusion| exclusion.path == path)
        {
            exclusion.reason = reason.into();
        } else {
            self.exclusions.push(ScanScopeExclusion {
                path,
                reason: reason.into(),
            });
        }
    }

    fn remove_exclusion(&mut self, path: &str) -> Result<()> {
        let index = self
            .exclusions
            .iter()
            .position(|exclusion| exclusion.path == path)
            .context("Choose an exact recorded exclusion path. No scope changed.")?;
        self.exclusions.remove(index);
        Ok(())
    }

    fn select_whole_repository(&mut self) {
        self.scopes = vec![ProposedScanScope {
            id: "repository".into(),
            name: "Whole repository".into(),
            paths: vec![".".into()],
            rationale: "Operator selected one whole-repository scope.".into(),
            shared_dependencies: Vec::new(),
            open_questions: Vec::new(),
        }];
        self.shared_scope = None;
        self.shared_discovery = false;
    }
}

fn primary_index(draft: &ScanScopeDraft, id: &str) -> Result<usize> {
    draft
        .scopes
        .iter()
        .position(|scope| scope.id == id)
        .with_context(|| {
            format!("scope {id:?} is not a primary scope; shared context is reviewed separately")
        })
}

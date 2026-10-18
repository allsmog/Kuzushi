use super::*;
use kuzushi_core::workspace::{ScanScopeEdit, ScopeFileFilter};

pub(crate) const SCOPE_ACTIONS: &[&str] = &[
    "Rename scope",
    "Split scope",
    "Merge into another scope",
    "Exclude selected scope",
    "Exclude a file or directory",
    "Edit boundary and questions",
    "Toggle shared discovery",
    "Use whole repository",
    "Review acceptance",
    "Build a new inventory draft",
    "Plan selected scope",
    "Include an excluded file or directory",
    "Suggest scan scopes with AI",
    "Use boundary as shared context",
    "Remove shared context",
    "Add discovery scope",
    "View saved findings",
    "Reload saved boundaries",
];

impl ShellApp {
    pub(super) fn apply_scope_menu(&mut self, index: usize) -> InputUpdate {
        match index {
            0 => self.open_scope_form(ScopeEditKind::Rename),
            1 => self.open_scope_form(ScopeEditKind::Split),
            2 => self.open_scope_merge(),
            3 => self.open_scope_form(ScopeEditKind::Exclude),
            4 => self.open_scope_form(ScopeEditKind::ExcludePath),
            5 => self.open_scope_form(ScopeEditKind::Boundary),
            _ => return self.apply_scope_plan_action(index),
        }
        InputUpdate::handled()
    }

    fn apply_scope_plan_action(&mut self, index: usize) -> InputUpdate {
        match index {
            6 => {
                let enabled = !self
                    .scope_review()
                    .and_then(|s| s.review.as_ref())
                    .is_some_and(|r| r.record.draft.shared_discovery);
                self.send_scope_edit(ScanScopeEdit::SetSharedDiscovery { enabled })
            }
            7 => self.send_scope_edit(ScanScopeEdit::WholeRepository),
            8 => {
                self.open_scope_acceptance();
                InputUpdate::handled()
            }
            10 => self.plan_selected_scope(),
            _ => return self.apply_scope_inventory_action(index),
        }
    }

    fn apply_scope_inventory_action(&mut self, index: usize) -> InputUpdate {
        match index {
            9 => self.dispatch_scope_request(json!({"operation":"create"})),
            11 => {
                self.open_scope_inclusion();
                InputUpdate::handled()
            }
            12 => self.open_scope_ai_priorities(),
            _ => self.apply_shared_context_menu(index),
        }
    }

    fn apply_shared_context_menu(&mut self, index: usize) -> InputUpdate {
        match index {
            16 => self.open_selected_scope_findings(),
            17 => self.refresh_scope_head(),
            13 => self.create_selected_shared_context(),
            14 => self.send_scope_edit(ScanScopeEdit::RemoveSharedContext),
            15 => {
                self.open_new_discovery_scope();
                InputUpdate::handled()
            }
            _ => InputUpdate::handled(),
        }
    }

    fn create_selected_shared_context(&mut self) -> InputUpdate {
        let Some(scope) = self.scope_review().and_then(selected_scope) else {
            self.scope_notice("Select a primary boundary to supply shared context.");
            return InputUpdate::handled();
        };
        self.send_scope_edit(ScanScopeEdit::CreateSharedContext {
            scope_id: scope.id.clone(),
            shared_scope_id: kuzushi_core::new_run_id("shared"),
        })
    }

    fn open_scope_inclusion(&mut self) {
        let Some(review) = self.scope_review().and_then(|state| state.review.clone()) else {
            return;
        };
        let Some(exclusion) = review.record.draft.exclusions.first() else {
            self.scope_notice("No recorded exclusions to include. Scope membership is unchanged.");
            return;
        };
        let Some(scope) = review.record.draft.scopes.first() else {
            return;
        };
        let mut form = ScopeEditForm::for_scope(ScopeEditKind::IncludePath, scope);
        form.fields[0].1 = crate::app::FieldEditor::new(&exclusion.path);
        let state = self.router.scope_review_mut().as_mut().unwrap();
        state.menu = None;
        state.form = Some(form);
        state.scroll = 0;
        state.notice = Some(format!("Remove only this exclusion rule. Current reason: {}. Coverage is recomputed; acceptance and scan approval remain separate.", exclusion.reason));
    }

    pub(super) fn send_scope_edit(&mut self, edit: ScanScopeEdit) -> InputUpdate {
        let Some(reference) = self
            .scope_review()
            .and_then(|s| s.review.as_ref())
            .map(|r| r.reference.clone())
        else {
            return InputUpdate::handled();
        };
        self.dispatch_scope_request(
            json!({"operation":"edit", "proposalRef":reference, "edit":edit}),
        )
    }

    fn open_scope_form(&mut self, kind: ScopeEditKind) {
        let scope = self.scope_review().and_then(selected_scope).cloned();
        let Some(scope) = scope else {
            self.scope_notice("Select a scope first.");
            return;
        };
        let state = self.router.scope_review_mut().as_mut().unwrap();
        state.menu = None;
        state.form = Some(ScopeEditForm::for_scope(kind, &scope));
        state.scroll = 0;
        state.notice = None;
    }

    fn open_scope_merge(&mut self) {
        if self
            .scope_review()
            .is_none_or(|s| merge_destinations(s).is_empty())
        {
            self.scope_notice("Select a primary scope with another primary scope available.");
            return;
        }
        let state = self.router.scope_review_mut().as_mut().unwrap();
        state.menu = None;
        state.merge_target = Some(0);
        state.scroll = 0;
        state.notice = None;
    }

    pub(super) fn complete_scope_merge(&mut self) -> InputUpdate {
        let Some(state) = self.scope_review() else {
            return InputUpdate::handled();
        };
        let Some((source, target)) = state.selected_id().zip(
            state
                .merge_target
                .and_then(|index| merge_destinations(state).get(index).cloned()),
        ) else {
            return InputUpdate::handled();
        };
        self.send_scope_edit(ScanScopeEdit::Merge {
            from_scope: source.into(),
            into_scope: target.id.clone(),
        })
    }

    pub(super) fn save_scope_form(&mut self) -> InputUpdate {
        if self
            .scope_review()
            .and_then(|state| state.form.as_ref())
            .is_some_and(|form| form.kind == ScopeEditKind::AiPriorities)
        {
            return self.prepare_scope_ai_study();
        }
        let Some(state) = self.scope_review() else {
            return InputUpdate::handled();
        };
        let Some((form, review)) = state.form.as_ref().zip(state.review.as_ref()) else {
            return InputUpdate::handled();
        };
        match form.edit(review.reference.revision.saturating_add(1)) {
            Ok(edit) => self.send_scope_edit(edit),
            Err(error) => {
                self.scope_notice(format!("{error:#}"));
                InputUpdate::handled()
            }
        }
    }

    pub(super) fn open_scope_acceptance(&mut self) {
        let Some(state) = self.router.scope_review_mut().as_mut() else {
            return;
        };
        state.menu = None;
        state.accepting = true;
        state.acknowledgements = Default::default();
        state.acknowledgement_cursor = 0;
        state.scroll = 0;
        state.notice = None;
    }

    pub(super) fn accept_scope_boundaries(&mut self) -> InputUpdate {
        let Some(state) = self.scope_review() else {
            return InputUpdate::handled();
        };
        let Some(review) = &state.review else {
            return InputUpdate::handled();
        };
        self.dispatch_scope_request(json!({"operation":"accept", "proposalRef":review.reference, "acknowledgements":state.acknowledgements}))
    }

    pub(super) fn request_scope_files(&mut self, offset: usize) -> InputUpdate {
        let Some(state) = self.scope_review() else {
            return InputUpdate::handled();
        };
        let Some(review) = &state.review else {
            return InputUpdate::handled();
        };
        let Some(filter) = selected_filter(state) else {
            self.scope_notice("Select a scope or coverage row to read files.");
            return InputUpdate::handled();
        };
        self.dispatch_scope_request(json!({"operation":"files", "proposalRef":review.reference, "fileFilter":filter, "offset":offset, "pageSize":32}))
    }
}

pub(crate) fn selected_scope(
    state: &ScopeReviewState,
) -> Option<&kuzushi_core::workspace::ProposedScanScope> {
    let review = state.review.as_ref()?;
    review
        .record
        .draft
        .scopes
        .iter()
        .chain(review.record.draft.shared_scope.iter())
        .nth(state.cursor)
}

pub(crate) fn merge_destinations(
    state: &ScopeReviewState,
) -> Vec<&kuzushi_core::workspace::ProposedScanScope> {
    let Some(review) = &state.review else {
        return Vec::new();
    };
    if !review
        .record
        .draft
        .scopes
        .iter()
        .any(|scope| Some(scope.id.as_str()) == state.selected_id())
    {
        return Vec::new();
    }
    review
        .record
        .draft
        .scopes
        .iter()
        .filter(|scope| Some(scope.id.as_str()) != state.selected_id())
        .collect()
}

pub(crate) fn selected_filter(state: &ScopeReviewState) -> Option<ScopeFileFilter> {
    if let Some(id) = state.selected_id() {
        return Some(ScopeFileFilter::Scope {
            scope_id: id.into(),
        });
    }
    let draft = &state.review.as_ref()?.record.draft;
    match state
        .cursor
        .checked_sub(draft.scopes.len() + usize::from(draft.shared_scope.is_some()))?
    {
        0 => Some(ScopeFileFilter::Uncovered),
        1 => Some(ScopeFileFilter::Excluded),
        2 => Some(ScopeFileFilter::Overlap),
        _ => None,
    }
}

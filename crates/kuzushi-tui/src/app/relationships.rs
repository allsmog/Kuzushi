//! Review relationships in a contextual reader with its own note field.
use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::findings::{
    FindingRelationship, FindingRelationshipPage, FindingRelationshipState,
};
use kuzushi_core::workspace::FindingRelationshipReviewRequest;
use std::path::PathBuf;
mod groups;
use groups::FindingGroupsRouteState;

mod state;
pub(crate) use state::{
    RelationshipBulkReview, RelationshipBulkStage, RelationshipNote, RelationshipWrite,
    RelationshipWriteDraft, RelationshipsRouteState,
};
mod bulk;
mod selection;
mod write;

impl ShellApp {
    pub(crate) fn open_relationships(&mut self) {
        let finding_id = crate::ui_view_models::visible_finding_at_cursor(self)
            .and_then(|(_, finding)| finding.id);
        self.router.relationships = RelationshipsRouteState {
            finding_id,
            ..Default::default()
        };
        self.set_shell_view(ShellView::Relationships);
    }

    pub(crate) fn relationship_page(
        &self,
    ) -> ViewDataState<Result<FindingRelationshipPage, String>> {
        self.workbench_cache().borrow().cached_relationships(
            self.target(),
            self.router.relationships.finding_id,
            self.router.relationships.offset,
        )
    }

    pub(crate) fn relationship_hydration_key(&self) -> ViewHydrationKey {
        if self.router.relationships.show_groups {
            return ViewHydrationKey::FindingGroups(
                self.router.relationships.groups.request.clone(),
            );
        }
        ViewHydrationKey::FindingRelationships {
            finding_id: self.router.relationships.finding_id,
            offset: self.router.relationships.offset,
        }
    }

    pub(crate) fn selected_relationship(&self) -> Option<FindingRelationship> {
        let ViewDataState::Ready(Ok(page)) = self.relationship_page() else {
            return None;
        };
        page.rows.get(self.router.relationships.cursor).cloned()
    }

    pub(crate) fn handle_relationship_key(
        &mut self,
        key: KeyEvent,
    ) -> Option<state_transitions::InputUpdate> {
        if self.handle_relationship_source_return_key(key) {
            return Some(state_transitions::InputUpdate::handled());
        }
        if !self.relationship_surface_owns_key(key) {
            return None;
        }
        self.handle_relationship_owned_key(key)
    }

    fn handle_relationship_source_return_key(&mut self, key: KeyEvent) -> bool {
        match (self.shell_view(), self.input_mode(), key.code) {
            (ShellView::Workbench, InputMode::Navigate, KeyCode::Char('G'))
                if key.modifiers.difference(KeyModifiers::SHIFT).is_empty() =>
            {
                self.return_to_relationship_bulk_review()
            }
            _ => false,
        }
    }

    fn handle_relationship_owned_key(
        &mut self,
        key: KeyEvent,
    ) -> Option<state_transitions::InputUpdate> {
        if let Some(update) = self.handle_relationship_form_key(key) {
            return Some(update);
        }
        if self.router.relationships.show_groups {
            return self.handle_group_key(key);
        }
        if !self.relationship_browse_enabled() {
            return None;
        }
        self.handle_relationship_browse_key(key)
    }

    fn handle_relationship_form_key(
        &mut self,
        key: KeyEvent,
    ) -> Option<state_transitions::InputUpdate> {
        if self.router.relationships.bulk.is_some() {
            return self.handle_relationship_bulk_key(key);
        }
        self.router.relationships.note.as_ref()?;
        Some(self.handle_relationship_note_key(key))
    }

    fn handle_relationship_browse_key(
        &mut self,
        key: KeyEvent,
    ) -> Option<state_transitions::InputUpdate> {
        if key.code == KeyCode::Tab && key.modifiers.is_empty() {
            self.open_finding_groups();
            return Some(state_transitions::InputUpdate::handled());
        }
        if key.code == KeyCode::Esc && key.modifiers.is_empty() {
            self.go_back();
            return Some(state_transitions::InputUpdate::handled());
        }
        let action = self
            .view_keybindings()
            .iter()
            .find(|binding| binding.matches(relationship_hotkey(key)))
            .map(|binding| binding.action)?;
        self.relationship_browse_action(action)
            .then(state_transitions::InputUpdate::handled)
    }

    fn relationship_surface_owns_key(&self, key: KeyEvent) -> bool {
        self.shell_view() == ShellView::Relationships
            && !(key.modifiers == KeyModifiers::CONTROL
                && matches!(key.code, KeyCode::Char('c' | 'd')))
    }
    fn relationship_browse_enabled(&self) -> bool {
        self.input_mode() == InputMode::Navigate
    }

    fn relationship_browse_action(&mut self, action: state_transitions::ViewHotkeyAction) -> bool {
        use state_transitions::ViewHotkeyAction::*;
        match action {
            RelationshipNext => self.move_relationship(1),
            RelationshipPrevious => self.move_relationship(-1),
            RelationshipAccept => self.begin_relationship_note(FindingRelationshipState::Accepted),
            RelationshipReject => self.begin_relationship_note(FindingRelationshipState::Rejected),
            RelationshipRemove => self.begin_relationship_note(FindingRelationshipState::Removed),
            RelationshipToggleSelection => self.toggle_relationship_selection(),
            RelationshipSelectPage => self.select_relationship_page(),
            RelationshipClearSelection => self.router.relationships.selection.clear(),
            RelationshipReviewSelection => self.open_relationship_bulk_review(),
            RelationshipsRefresh => self.refresh_relationships(),
            RelationshipsNextPage => self.next_relationship_page(),
            RelationshipsPreviousPage => self.previous_relationship_page(),
            _ => return false,
        }
        true
    }

    fn move_relationship(&mut self, delta: isize) {
        let ViewDataState::Ready(Ok(page)) = self.relationship_page() else {
            return;
        };
        let route = &mut self.router.relationships;
        route.cursor = route
            .cursor
            .saturating_add_signed(delta)
            .min(page.rows.len().saturating_sub(1));
        self.router.default_scroll_mut().set(0);
    }

    fn next_relationship_page(&mut self) {
        let ViewDataState::Ready(Ok(page)) = self.relationship_page() else {
            return;
        };
        if !page.has_more {
            return;
        }
        self.router.relationships.offset += 50;
        self.router.relationships.cursor = 0;
    }

    fn previous_relationship_page(&mut self) {
        self.router.relationships.offset = self.router.relationships.offset.saturating_sub(50);
        self.router.relationships.cursor = 0;
    }

    fn begin_relationship_note(&mut self, state: FindingRelationshipState) {
        if self.runtime_state.relationship_write.is_some() {
            return;
        }
        let Some(relationship) = self.selected_relationship() else {
            return;
        };
        let Some(target) = self.target_owned() else {
            return;
        };
        self.router.relationships.notice = None;
        self.router.relationships.note = Some(RelationshipNote {
            target,
            relationship,
            state,
            field: FieldEditor::default(),
        });
    }

    fn handle_relationship_note_key(&mut self, key: KeyEvent) -> state_transitions::InputUpdate {
        match key.code {
            KeyCode::Esc => self.router.relationships.note = None,
            KeyCode::Enter if key.modifiers.contains(KeyModifiers::SHIFT) => self
                .router
                .relationships
                .note
                .as_mut()
                .unwrap()
                .field
                .insert("\n"),
            KeyCode::Enter => self.submit_relationship_note(),
            _ => {
                self.router
                    .relationships
                    .note
                    .as_mut()
                    .unwrap()
                    .field
                    .handle_key(key);
            }
        }
        state_transitions::InputUpdate::handled()
    }

    pub(crate) fn paste_relationship_note(&mut self, text: &str) -> bool {
        if self.shell_view() != ShellView::Relationships {
            return false;
        }
        if let Some(bulk) = self.router.relationships.bulk.as_mut() {
            if bulk.stage == RelationshipBulkStage::Reason {
                bulk.field.insert(text);
            }
            return true;
        }
        let Some(note) = self.router.relationships.note.as_mut() else {
            return false;
        };
        note.field.insert(text);
        true
    }

    fn submit_relationship_note(&mut self) {
        let Some(note) = self.router.relationships.note.as_ref() else {
            return;
        };
        if note.field.text().trim().is_empty() {
            self.router.relationships.notice =
                Some("A relationship decision needs a reason.".into());
            return;
        }
        if self.target() != Some(note.target.as_path()) {
            self.router.relationships.notice =
                Some("Target changed. Return to the recorded target before deciding.".into());
            return;
        }
        self.spawn_relationship_write(note.clone());
    }

    fn refresh_relationships(&mut self) {
        self.workbench_cache()
            .borrow_mut()
            .relationship_pages
            .clear();
        self.router.relationships.notice = None;
    }
}

fn relationship_hotkey(mut key: KeyEvent) -> KeyEvent {
    if key.code == KeyCode::Char('*') && key.modifiers == KeyModifiers::SHIFT {
        key.modifiers = KeyModifiers::NONE;
    }
    key
}

#[cfg(test)]
mod tests;

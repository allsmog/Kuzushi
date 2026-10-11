use super::*;

impl ShellApp {
    pub(super) fn open_relationship_bulk_review(&mut self) {
        if self.runtime_state.relationship_write.is_some() {
            return;
        }
        let Some(target) = self.target_owned() else {
            return;
        };
        let records = self.router.relationships.selection.clone();
        if records.is_empty() {
            self.router.relationships.notice = Some(
                "Space selects a relationship; * selects this page. A reviews the selected set."
                    .into(),
            );
            return;
        }
        self.router.relationships.bulk = Some(RelationshipBulkReview {
            target,
            records,
            cursor: 0,
            stage: RelationshipBulkStage::Review,
            state: FindingRelationshipState::Accepted,
            field: FieldEditor::default(),
            origin_scroll: self.router.default_scroll().offset(),
            review_scroll: 0,
            inspecting_destination: false,
            return_from_source: false,
            source_scroll: 0,
        });
        self.router.relationships.notice = None;
        self.router.default_scroll_mut().set(0);
    }

    pub(super) fn handle_relationship_bulk_key(
        &mut self,
        key: KeyEvent,
    ) -> Option<state_transitions::InputUpdate> {
        let stage = self.router.relationships.bulk.as_ref()?.stage;
        if stage != RelationshipBulkStage::Reason
            && matches!(
                key.code,
                KeyCode::PageUp | KeyCode::PageDown | KeyCode::Home | KeyCode::End
            )
        {
            return None;
        }
        match stage {
            RelationshipBulkStage::Review => self.relationship_bulk_review_key(key.code),
            RelationshipBulkStage::Reason => self.relationship_bulk_reason_key(key),
            RelationshipBulkStage::Confirm => self.relationship_bulk_confirm_key(key.code),
        }
        Some(state_transitions::InputUpdate::handled())
    }

    fn relationship_bulk_review_key(&mut self, key: KeyCode) {
        if self.relationship_bulk_source_key(key) {
            return;
        }
        match key {
            KeyCode::Char('a') => {
                self.set_relationship_bulk_decision(FindingRelationshipState::Accepted)
            }
            KeyCode::Char('r') => {
                self.set_relationship_bulk_decision(FindingRelationshipState::Rejected)
            }
            KeyCode::Char('u') => {
                self.set_relationship_bulk_decision(FindingRelationshipState::Removed)
            }
            KeyCode::Char('j') | KeyCode::Down => self.move_relationship_bulk_cursor(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_relationship_bulk_cursor(-1),
            KeyCode::Esc => self.close_relationship_bulk_review(),
            _ => {}
        }
    }

    fn relationship_bulk_source_key(&mut self, key: KeyCode) -> bool {
        match key {
            KeyCode::Char('[') => self.select_relationship_bulk_endpoint(false),
            KeyCode::Char(']') => self.select_relationship_bulk_endpoint(true),
            KeyCode::Enter => self.open_relationship_bulk_source(),
            _ => return false,
        }
        true
    }

    fn select_relationship_bulk_endpoint(&mut self, destination: bool) {
        self.router
            .relationships
            .bulk
            .as_mut()
            .unwrap()
            .inspecting_destination = destination;
        self.router.default_scroll_mut().set(0);
    }

    fn open_relationship_bulk_source(&mut self) {
        let review = self.router.relationships.bulk.as_ref().unwrap();
        if self.target() != Some(review.target.as_path()) {
            self.router.relationships.notice =
                Some("Return to the reviewed target before opening its recorded source.".into());
            return;
        }
        let record = &review.records[review.cursor];
        let id = if review.inspecting_destination {
            record.to.finding_id
        } else {
            record.from.finding_id
        };
        let scroll = self.router.default_scroll().offset();
        let review = self.router.relationships.bulk.as_mut().unwrap();
        review.return_from_source = true;
        review.source_scroll = scroll;
        let effects = self.open_finding_effects(&format!("generation:{id}"));
        EffectRuntime::execute(self, effects);
        if self.shell_view() == ShellView::Workbench {
            self.set_info_notice("relationships", "G returns to the reviewed selection.");
        } else {
            self.router
                .relationships
                .bulk
                .as_mut()
                .unwrap()
                .return_from_source = false;
        }
    }

    pub(crate) fn return_to_relationship_bulk_review(&mut self) -> bool {
        let Some(review) = self.router.relationships.bulk.as_ref() else {
            return false;
        };
        if !review.return_from_source {
            return false;
        }
        let scroll = review.source_scroll;
        self.router
            .relationships
            .bulk
            .as_mut()
            .unwrap()
            .return_from_source = false;
        self.set_shell_view(ShellView::Relationships);
        self.set_input_mode(InputMode::Navigate);
        self.router.default_scroll_mut().set(scroll);
        self.clear_relationship_source_notice();
        true
    }

    fn clear_relationship_source_notice(&mut self) {
        let is_return_notice = self.advisory().notice.as_ref().is_some_and(|notice| {
            notice.source == "relationships"
                && notice.message == "G returns to the reviewed selection."
        });
        if is_return_notice {
            self.clear_notice();
        }
    }

    fn move_relationship_bulk_cursor(&mut self, delta: isize) {
        let bulk = self.router.relationships.bulk.as_mut().unwrap();
        bulk.cursor = bulk
            .cursor
            .saturating_add_signed(delta)
            .min(bulk.records.len() - 1);
        self.router.default_scroll_mut().set(0);
    }

    fn set_relationship_bulk_decision(&mut self, state: FindingRelationshipState) {
        let scroll = self.router.default_scroll().offset();
        let bulk = self.router.relationships.bulk.as_mut().unwrap();
        bulk.review_scroll = scroll;
        bulk.state = state;
        bulk.stage = RelationshipBulkStage::Reason;
        self.router.default_scroll_mut().set(0);
    }

    fn relationship_bulk_reason_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => self.restore_relationship_bulk_review(),
            KeyCode::Enter if key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.router
                    .relationships
                    .bulk
                    .as_mut()
                    .unwrap()
                    .field
                    .insert("\n");
            }
            KeyCode::Enter => self.preview_relationship_bulk_confirmation(),
            _ => {
                self.router
                    .relationships
                    .bulk
                    .as_mut()
                    .unwrap()
                    .field
                    .handle_key(key);
            }
        }
    }

    fn restore_relationship_bulk_review(&mut self) {
        let bulk = self.router.relationships.bulk.as_mut().unwrap();
        bulk.stage = RelationshipBulkStage::Review;
        let scroll = bulk.review_scroll;
        self.router.default_scroll_mut().set(scroll);
    }

    fn preview_relationship_bulk_confirmation(&mut self) {
        let bulk = self.router.relationships.bulk.as_mut().unwrap();
        if bulk.field.text().trim().is_empty() {
            self.router.relationships.notice =
                Some("Enter a reason before reviewing the confirmation.".into());
            return;
        }
        bulk.stage = RelationshipBulkStage::Confirm;
        self.router.relationships.notice = None;
        self.router.default_scroll_mut().set(0);
    }

    fn relationship_bulk_confirm_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Enter => self.submit_relationship_bulk_review(),
            KeyCode::Esc => {
                self.router.relationships.bulk.as_mut().unwrap().stage =
                    RelationshipBulkStage::Reason;
                self.router.default_scroll_mut().set(0);
            }
            _ => {}
        }
    }

    fn submit_relationship_bulk_review(&mut self) {
        let review = self.router.relationships.bulk.as_ref().unwrap();
        if self.target() != Some(review.target.as_path()) {
            self.router.relationships.notice =
                Some("Target changed. Return to the reviewed target before confirming.".into());
            return;
        }
        self.spawn_relationship_bulk_write(review.clone());
    }

    fn close_relationship_bulk_review(&mut self) {
        let review = self.router.relationships.bulk.take().unwrap();
        self.router.default_scroll_mut().set(review.origin_scroll);
        self.router.relationships.notice = None;
    }
}

#[cfg(test)]
mod tests;

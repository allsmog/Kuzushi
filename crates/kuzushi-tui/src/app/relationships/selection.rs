use super::*;

impl ShellApp {
    pub(super) fn toggle_relationship_selection(&mut self) {
        if !self.relationship_selection_writable() {
            return;
        }
        let Some(record) = self.selected_relationship() else {
            return;
        };
        if let Some(index) = self
            .router
            .relationships
            .selection
            .iter()
            .position(|row| row.id == record.id)
        {
            self.router.relationships.selection.remove(index);
            return;
        }
        self.pin_relationship(record.clone());
        self.extend_relationship_selection(vec![record]);
    }

    pub(super) fn select_relationship_page(&mut self) {
        if !self.relationship_selection_writable() {
            return;
        }
        let ViewDataState::Ready(Ok(page)) = self.relationship_page() else {
            return;
        };
        self.extend_relationship_selection(page.rows);
    }

    fn relationship_selection_writable(&mut self) -> bool {
        if self.runtime_state.relationship_write.is_none() {
            return true;
        }
        self.router.relationships.notice = Some(
            "The reviewed selection is being saved. Wait for its receipt before selecting more."
                .into(),
        );
        false
    }

    fn extend_relationship_selection(&mut self, rows: Vec<FindingRelationship>) {
        let mut selection = self.router.relationships.selection.clone();
        for row in rows {
            if !selection.iter().any(|selected| selected.id == row.id) {
                selection.push(row);
            }
        }
        if selection.len() > 50 {
            self.router.relationships.notice = Some(
                "Choose at most 50 relationships. The previous selection is preserved.".into(),
            );
            return;
        }
        self.router.relationships.selection = selection;
        self.router.relationships.notice = None;
    }
}

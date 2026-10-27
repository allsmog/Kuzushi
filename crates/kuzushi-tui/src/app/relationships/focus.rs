use super::*;

impl ShellApp {
    pub(crate) fn selected_relationship(&self) -> Option<FindingRelationship> {
        let ViewDataState::Ready(Ok(page)) = self.relationship_page() else {
            return None;
        };
        let visible = self
            .relationship_cursor(&page)
            .and_then(|index| page.rows.get(index));
        preferred_record(visible, self.router.relationships.pinned.as_ref()).cloned()
    }

    pub(crate) fn relationship_cursor(&self, page: &FindingRelationshipPage) -> Option<usize> {
        if let Some(record) = &self.router.relationships.pinned {
            return page.rows.iter().position(|row| row.id == record.id);
        }
        (!page.rows.is_empty()).then(|| self.router.relationships.cursor.min(page.rows.len() - 1))
    }

    pub(super) fn pin_relationship(&mut self, record: FindingRelationship) {
        self.router.relationships.pinned = Some(record);
    }

    pub(super) fn pin_current_relationship(&mut self) {
        if let Some(record) = self.selected_relationship() {
            self.pin_relationship(record);
        }
    }

    pub(super) fn move_relationship(&mut self, delta: isize) {
        let ViewDataState::Ready(Ok(page)) = self.relationship_page() else {
            return;
        };
        let cursor = self
            .relationship_cursor(&page)
            .map_or(0, |index| index.saturating_add_signed(delta))
            .min(page.rows.len().saturating_sub(1));
        self.router.relationships.cursor = cursor;
        self.router.relationships.pinned = page.rows.get(cursor).cloned();
        self.router.default_scroll_mut().set(0);
    }

    pub(super) fn next_relationship_page(&mut self) {
        let ViewDataState::Ready(Ok(page)) = self.relationship_page() else {
            return;
        };
        if page.has_more {
            self.change_relationship_page(self.router.relationships.offset + 50);
        }
    }

    pub(super) fn previous_relationship_page(&mut self) {
        self.change_relationship_page(self.router.relationships.offset.saturating_sub(50));
    }

    fn change_relationship_page(&mut self, offset: usize) {
        self.router.relationships.offset = offset;
        self.router.relationships.cursor = 0;
        self.router.relationships.pinned = None;
        self.router.default_scroll_mut().set(0);
    }
}

fn preferred_record<'a>(
    visible: Option<&'a FindingRelationship>,
    recorded: Option<&'a FindingRelationship>,
) -> Option<&'a FindingRelationship> {
    match (visible, recorded) {
        (Some(visible), Some(recorded)) if recorded.revision > visible.revision => Some(recorded),
        (visible, recorded) => visible.or(recorded),
    }
}

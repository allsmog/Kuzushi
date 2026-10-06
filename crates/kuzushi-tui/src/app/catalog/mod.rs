use super::*;
pub(crate) use super::*;
use crate::ui_view_models::{catalog_model, CatalogModel};

impl ShellApp {
    pub fn catalog_module_count(&self) -> usize {
        catalog_model(self).module_count
    }

    pub fn catalog_cursor_command(&self) -> Option<String> {
        let model = catalog_model(self);
        let commands = catalog_action_commands(&model);
        let cursor = self.router.catalog().cursor();
        commands
            .get(cursor.min(commands.len().saturating_sub(1)))
            .cloned()
    }

    pub fn catalog_cursor_module_id(&self) -> Option<String> {
        let model = catalog_model(self);
        let ids = catalog_action_ids(&model);
        let cursor = self.router.catalog().cursor();
        ids.get(cursor.min(ids.len().saturating_sub(1))).cloned()
    }

    pub fn move_catalog_cursor(&mut self, delta: i32) {
        let count = self.catalog_module_count();
        self.router.catalog_mut().move_cursor(delta, count);
        self.keep_catalog_selection_visible();
    }

    /// The overlay reserves rows for the cockpit chrome, capability header,
    /// NEXT action, and category rails; the rest is the action-row budget that
    /// keeps the selection inside the modal and sizes one page of paging.
    pub(crate) fn catalog_visible_rows(&self) -> usize {
        usize::from(self.viewport().rows.saturating_sub(17)).max(3)
    }

    fn keep_catalog_selection_visible(&mut self) {
        let cursor = self.router.catalog().cursor();
        let visible_rows = self.catalog_visible_rows();
        let scroll = self.router.modules().scroll();
        let next = if cursor < scroll {
            cursor
        } else if cursor >= scroll.saturating_add(visible_rows) {
            cursor.saturating_add(1).saturating_sub(visible_rows)
        } else {
            scroll
        };
        *self.router.modules_mut().scroll_mut() = next;
    }
}

fn catalog_action_ids(model: &CatalogModel) -> Vec<String> {
    model
        .groups
        .iter()
        .flat_map(|group| group.rows.iter().map(|row| row.id.clone()))
        .collect()
}

fn catalog_action_commands(model: &CatalogModel) -> Vec<String> {
    model
        .groups
        .iter()
        .flat_map(|group| group.rows.iter().map(|row| row.command.clone()))
        .collect()
}

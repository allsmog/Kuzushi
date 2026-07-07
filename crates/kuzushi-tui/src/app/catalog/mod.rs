use super::*;
pub(crate) use super::*;
use crate::ui_view_models::{catalog_model, CatalogModel};

impl ShellApp {
    pub fn catalog_module_count(&self) -> usize {
        catalog_model(self).module_count
    }

    pub fn catalog_cursor_module_id(&self) -> Option<String> {
        let model = catalog_model(self);
        let modules = catalog_module_ids(&model);
        modules
            .get(
                self.catalog_route
                    .cursor()
                    .min(modules.len().saturating_sub(1)),
            )
            .cloned()
    }

    pub fn move_catalog_cursor(&mut self, delta: i32) {
        self.catalog_route
            .move_cursor(delta, self.catalog_module_count());
    }
}

fn catalog_module_ids(model: &CatalogModel) -> Vec<String> {
    model
        .groups
        .iter()
        .flat_map(|group| group.rows.iter().map(|row| row.id.clone()))
        .collect()
}

use super::{wrapped_cursor, MapRunConfigRowId};
use crate::app::FieldEditor;
mod scope_picker;
use scope_picker::MapScopePicker;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MapRunConfigRouteState {
    cursor: usize,
    text: Option<MapTextList>,
    scope: Option<MapScopePicker>,
    error: Option<String>,
    reviewed_all_scope_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MapTextList {
    pub(crate) row: MapRunConfigRowId,
    pub(crate) values: Vec<String>,
    pub(crate) cursor: usize,
    pub(crate) field: Option<FieldEditor>,
}

impl MapTextList {
    fn new(row: MapRunConfigRowId, values: Vec<String>) -> Self {
        let field = values.is_empty().then(FieldEditor::default);
        Self {
            row,
            values,
            cursor: 0,
            field,
        }
    }

    pub(crate) fn move_cursor(&mut self, delta: isize) {
        self.cursor = wrapped_cursor(self.cursor, delta, self.values.len() + 1);
    }

    pub(crate) fn edit_selected(&mut self) {
        self.field = Some(FieldEditor::new(
            self.values.get(self.cursor).cloned().unwrap_or_default(),
        ));
    }

    pub(crate) fn add(&mut self) {
        self.cursor = self.values.len();
        self.edit_selected();
    }

    pub(crate) fn candidate_values(&self, value: String) -> Vec<String> {
        let mut values = self.values.clone();
        if self.cursor < values.len() {
            values[self.cursor] = value;
        } else {
            values.push(value);
        }
        values
    }

    pub(crate) fn without_selected(&self) -> Vec<String> {
        let mut values = self.values.clone();
        if self.cursor < values.len() {
            values.remove(self.cursor);
        }
        values
    }

    pub(crate) fn saved(&mut self, values: Vec<String>) {
        self.values = values;
        self.cursor = self.cursor.min(self.values.len());
        self.field = None;
    }
}

impl MapRunConfigRouteState {
    pub(crate) fn open(&mut self) {
        self.scope = None;
        self.text = None;
        self.error = None;
        self.cursor = self
            .cursor
            .min(MapRunConfigRowId::ALL.len().saturating_sub(1));
    }

    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    pub(crate) fn row(&self) -> MapRunConfigRowId {
        MapRunConfigRowId::ALL[self.cursor.min(MapRunConfigRowId::ALL.len() - 1)]
    }

    pub(crate) fn move_cursor(&mut self, delta: isize) {
        self.cursor = wrapped_cursor(self.cursor, delta, MapRunConfigRowId::ALL.len());
        self.error = None;
    }

    pub(crate) fn begin_edit(&mut self, row: MapRunConfigRowId, values: Vec<String>) {
        self.scope = None;
        self.text = Some(MapTextList::new(row, values));
        self.error = None;
    }

    pub(crate) fn finish_edit(&mut self) {
        self.text = None;
        self.error = None;
    }

    pub(crate) fn begin_scope(
        &mut self,
        choices: Vec<(Option<String>, String)>,
        selected: Option<&str>,
    ) {
        self.text = None;
        self.scope = Some(MapScopePicker::new(choices, selected));
        self.error = None;
    }

    pub(crate) fn scope(&self) -> Option<&MapScopePicker> {
        self.scope.as_ref()
    }
    pub(crate) fn scope_mut(&mut self) -> Option<&mut MapScopePicker> {
        self.scope.as_mut()
    }
    pub(crate) fn finish_scope(&mut self) {
        self.scope = None;
        self.error = None;
    }

    pub(crate) fn text(&self) -> Option<&MapTextList> {
        self.text.as_ref()
    }

    pub(crate) fn text_mut(&mut self) -> Option<&mut MapTextList> {
        self.text.as_mut()
    }

    pub(crate) fn has_unsaved_text(&self) -> bool {
        let Some(list) = &self.text else {
            return false;
        };
        list.field.as_ref().is_some_and(|field| {
            field.text()
                != list
                    .values
                    .get(list.cursor)
                    .map(String::as_str)
                    .unwrap_or_default()
        })
    }

    pub(crate) fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub(crate) fn set_error(&mut self, error: impl Into<String>) {
        self.error = Some(error.into());
    }

    pub(crate) fn clear_error(&mut self) {
        self.error = None;
    }

    pub(crate) fn all_scopes_reviewed(&self, key: &str) -> bool {
        self.reviewed_all_scope_key.as_deref() == Some(key)
    }

    pub(crate) fn set_all_scopes_reviewed(&mut self, key: Option<String>) {
        self.reviewed_all_scope_key = key;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn individual_entries_preserve_paths_and_complete_prose() {
        let original = vec![
            "docs/Architecture, v2.md".into(),
            "line one,\nline two".into(),
        ];
        let mut list = MapTextList::new(MapRunConfigRowId::Context, original.clone());
        list.cursor = 1;
        list.edit_selected();
        let unchanged = list.candidate_values(list.field.as_ref().unwrap().text().into());
        assert_eq!(unchanged, original);
        list.saved(unchanged);
        list.add();
        let with_new = list.candidate_values("third, complete entry".into());
        assert_eq!(with_new.len(), 3);
        assert_eq!(with_new[2], "third, complete entry");
    }

    #[test]
    fn canceling_an_entry_does_not_mutate_saved_values() {
        let mut list = MapTextList::new(MapRunConfigRowId::DesignDocs, vec!["original.md".into()]);
        list.edit_selected();
        list.field.as_mut().unwrap().insert("draft");
        list.field = None;
        assert_eq!(list.values, ["original.md"]);
        assert!(list.without_selected().is_empty());
    }
}

use crate::app::FieldEditor;
use crossterm::event::{KeyCode, KeyEvent};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MapScopeChoice {
    pub(crate) value: Option<String>,
    pub(crate) label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MapScopePicker {
    choices: Vec<MapScopeChoice>,
    pub(crate) query: FieldEditor,
    pub(crate) cursor: usize,
    pub(crate) pending_review: Option<String>,
}

impl MapScopePicker {
    pub(super) fn new(choices: Vec<(Option<String>, String)>, selected: Option<&str>) -> Self {
        let cursor = choices
            .iter()
            .position(|(value, _)| value.as_deref() == selected)
            .unwrap_or(0);
        Self {
            choices: choices
                .into_iter()
                .map(|(value, label)| MapScopeChoice { value, label })
                .collect(),
            query: FieldEditor::default(),
            cursor,
            pending_review: None,
        }
    }

    pub(crate) fn refresh_label(&mut self, value: &str, label: String) {
        if let Some(choice) = self
            .choices
            .iter_mut()
            .find(|choice| choice.value.as_deref() == Some(value))
        {
            choice.label = label;
        }
    }

    pub(crate) fn filtered(&self) -> Vec<&MapScopeChoice> {
        let query = self.query.text().trim().to_lowercase();
        self.choices
            .iter()
            .filter(|choice| scope_matches(choice, &query))
            .collect()
    }

    pub(crate) fn selected(&self) -> Option<&MapScopeChoice> {
        self.filtered().get(self.cursor).copied()
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) {
        let previous = self.query.text().to_string();
        if key.modifiers.is_empty() {
            self.move_selection(key.code);
        }
        if !matches!(
            key.code,
            KeyCode::Up | KeyCode::Down | KeyCode::PageUp | KeyCode::PageDown
        ) {
            self.query.handle_key(key);
        }
        if self.query.text() != previous {
            self.cursor = 0;
        }
        self.pending_review = None;
    }

    fn move_selection(&mut self, code: KeyCode) {
        let delta = match code {
            KeyCode::Up => -1,
            KeyCode::Down => 1,
            KeyCode::PageUp => -10,
            KeyCode::PageDown => 10,
            _ => return,
        };
        self.cursor = self
            .cursor
            .saturating_add_signed(delta)
            .min(self.filtered().len().saturating_sub(1));
    }

    pub(crate) fn paste(&mut self, text: &str) {
        self.query.insert(text);
        self.cursor = 0;
        self.pending_review = None;
    }
}

fn scope_matches(choice: &MapScopeChoice, query: &str) -> bool {
    choice.label.to_lowercase().contains(query)
        || choice
            .value
            .as_deref()
            .unwrap_or_default()
            .to_lowercase()
            .contains(query)
}

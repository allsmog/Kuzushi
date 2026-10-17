//! Filter existing actions without changing their dispatch identities.
use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

impl ScopeReviewState {
    pub(crate) fn matching_actions(&self) -> Vec<usize> {
        let query = self.menu_search.as_ref().map_or("", |field| field.text());
        let query = query.to_lowercase();
        SCOPE_ACTIONS
            .iter()
            .enumerate()
            .filter(|(_, label)| {
                let label = label.to_lowercase();
                query.split_whitespace().all(|word| label.contains(word))
            })
            .map(|(index, _)| index)
            .collect()
    }

    fn reconcile_action_selection(&mut self) {
        let matches = self.matching_actions();
        if !self.menu.is_some_and(|index| matches.contains(&index)) {
            self.menu = Some(matches.first().copied().unwrap_or(0));
        }
        self.scroll = 0;
        self.notice = None;
    }

    pub(super) fn paste_action_search(&mut self, text: &str) {
        let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
        let text: String = text.chars().filter(|ch| !ch.is_control()).collect();
        self.menu_search
            .get_or_insert_with(Default::default)
            .insert(&text);
        self.reconcile_action_selection();
    }

    fn edit_action_search(&mut self, key: KeyEvent) {
        self.menu_search.as_mut().unwrap().handle_key(key);
        self.reconcile_action_selection();
    }

    fn move_action_search(&mut self, backwards: bool) {
        let matches = self.matching_actions();
        let current = matches
            .iter()
            .position(|index| Some(*index) == self.menu)
            .unwrap_or(0);
        let next = if backwards {
            current.saturating_sub(1)
        } else {
            current.saturating_add(1)
        };
        self.menu = matches
            .get(next.min(matches.len().saturating_sub(1)))
            .copied()
            .or(Some(0));
        self.scroll = 0;
    }
}

impl ShellApp {
    pub(super) fn scope_action_search_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        let state = self.router.scope_review_mut().as_mut()?;
        state.menu?;
        if begins_search(key) && state.menu_search.is_none() {
            state.menu_search = Some(Default::default());
            state.reconcile_action_selection();
            return Some(InputUpdate::handled());
        }
        state.menu_search.as_ref()?;
        if matches!(key.code, KeyCode::PageUp | KeyCode::PageDown) {
            return None;
        }
        Some(self.reduce_action_search(key))
    }

    fn reduce_action_search(&mut self, key: KeyEvent) -> InputUpdate {
        if key.code == KeyCode::Enter && key.modifiers.is_empty() {
            return self.choose_searched_action();
        }
        let state = self.router.scope_review_mut().as_mut().unwrap();
        if let Some(backwards) = navigation_direction(key) {
            state.move_action_search(backwards);
        } else {
            state.edit_action_search(key);
        }
        InputUpdate::handled()
    }

    fn choose_searched_action(&mut self) -> InputUpdate {
        let state = self.scope_review().unwrap();
        let Some(index) = state
            .menu
            .filter(|index| state.matching_actions().contains(index))
        else {
            self.scope_notice("No matching actions. Edit the search or Esc to show all actions.");
            return InputUpdate::handled();
        };
        let update = self.apply_scope_menu(index);
        if let Some(state) = self
            .router
            .scope_review_mut()
            .as_mut()
            .filter(|state| state.menu.is_none() || !state.open)
        {
            state.menu_search = None;
        }
        update
    }
}

fn begins_search(key: KeyEvent) -> bool {
    key.code == KeyCode::Char('/')
        && matches!(key.modifiers, KeyModifiers::NONE | KeyModifiers::SHIFT)
}

fn navigation_direction(key: KeyEvent) -> Option<bool> {
    match (key.code, key.modifiers) {
        (KeyCode::Up, KeyModifiers::NONE | KeyModifiers::SHIFT) => Some(true),
        (KeyCode::Down, KeyModifiers::NONE | KeyModifiers::SHIFT) => Some(false),
        _ => None,
    }
}

pub(super) fn cancel_search(state: &mut ScopeReviewState) -> bool {
    if state.menu.is_none() {
        return false;
    }
    if state.menu_search.take().is_none() {
        return false;
    }
    state.scroll = 0;
    state.notice = None;
    true
}

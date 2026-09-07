use super::*;

const ENTRY_SEARCH_MAX_CHARS: usize = 512;

impl ShellApp {
    pub(crate) fn entry_point_search_owns_input(&self) -> bool {
        self.router.scene().entry_point_searching() && self.entry_point_surface_is_visible()
    }

    fn entry_point_surface_is_visible(&self) -> bool {
        match self.shell_view() {
            ShellView::Scene => self.router.scene().page() == crate::scene3d::VizPage::EntryPoints,
            ShellView::Workbench => {
                crate::ui_view_models::active_workbench_page(self) == WorkbenchPage::Map
                    && crate::ui_view_models::map_gallery_is_primary(self)
                    && self.current_map_viz_page() == crate::scene3d::VizPage::EntryPoints
            }
            _ => false,
        }
    }

    pub(super) fn handle_entry_point_search_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if !self.entry_point_search_owns_input() {
            return None;
        }
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return None;
        }
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                self.router.scene_mut().set_entry_point_searching(false)
            }
            KeyCode::Backspace => {
                self.router.scene_mut().entry_point_query_mut().pop();
                self.select_first_entry_point_match();
            }
            KeyCode::Char(ch) => self.append_entry_point_search(&ch.to_string()),
            _ => return Some(InputUpdate::handled()),
        }
        Some(InputUpdate::handled())
    }

    pub(crate) fn paste_entry_point_search(&mut self, text: &str) -> bool {
        if !self.entry_point_search_owns_input() {
            return false;
        }
        self.append_entry_point_search(text);
        true
    }

    fn append_entry_point_search(&mut self, text: &str) {
        let current = self.router.scene().entry_point_query().chars().count();
        let room = ENTRY_SEARCH_MAX_CHARS.saturating_sub(current);
        let text = text
            .chars()
            .filter_map(search_character)
            .take(room)
            .collect::<String>();
        self.router
            .scene_mut()
            .entry_point_query_mut()
            .push_str(&text);
        self.select_first_entry_point_match();
    }

    pub(super) fn select_first_entry_point_match(&mut self) {
        self.bind_entry_point_browser_index(0);
    }

    pub(super) fn bind_entry_point_browser_index(&mut self, index: usize) {
        let model = crate::ui_view_models::entry_point_browser_model(self);
        let index = index.min(model.entries.len().saturating_sub(1));
        let id = model.entries.get(index).map(|entry| entry.id.clone());
        self.router
            .scene_mut()
            .bind_entry_point_selection(id, index, model.entries.len());
    }
}

fn search_character(ch: char) -> Option<char> {
    if ch.is_whitespace() {
        return Some(' ');
    }
    (!ch.is_control()).then_some(ch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_paste_never_turns_newlines_into_submissions_or_joins_words() {
        assert_eq!(
            "path:auth\nkind:parser\u{1b}"
                .chars()
                .filter_map(search_character)
                .collect::<String>(),
            "path:auth kind:parser"
        );
    }
}

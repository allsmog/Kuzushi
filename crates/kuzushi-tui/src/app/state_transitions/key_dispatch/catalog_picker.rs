use super::*;

impl ShellApp {
    pub(crate) fn catalog_picker_owns_input(&self) -> bool {
        self.shell_view() == ShellView::Catalog && self.input().is_empty()
    }

    pub(super) fn catalog_composer_owns_input(&self) -> bool {
        self.shell_view() == ShellView::Catalog && !self.input().is_empty()
    }

    pub(super) fn handle_catalog_picker_key(&mut self, key: KeyEvent) -> bool {
        if !self.catalog_picker_owns_input() {
            return false;
        }
        if let Some(delta) = catalog_cursor_delta(key.code, self.catalog_visible_rows()) {
            self.move_catalog_cursor(delta);
            return true;
        }
        self.handle_catalog_action_key(key)
    }

    fn handle_catalog_action_key(&mut self, key: KeyEvent) -> bool {
        let binding = self
            .view_keybindings()
            .into_iter()
            .find(|binding| catalog_picker_action(binding.action) && binding.matches(key));
        binding.is_some_and(|binding| self.apply_view_hotkey(binding.action).handled)
    }
}

fn catalog_cursor_delta(code: KeyCode, page_rows: usize) -> Option<i32> {
    let page = i32::try_from(page_rows).unwrap_or(i32::MAX);
    match code {
        KeyCode::Up => Some(-1),
        KeyCode::Down => Some(1),
        KeyCode::PageUp => Some(-page),
        KeyCode::PageDown => Some(page),
        _ => None,
    }
}

fn catalog_picker_action(action: ViewHotkeyAction) -> bool {
    matches!(
        action,
        ViewHotkeyAction::CatalogActivate
            | ViewHotkeyAction::CatalogToggleExpert
            | ViewHotkeyAction::CatalogRefreshDependencies
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog_app() -> ShellApp {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(std::path::PathBuf::from(".")));
        app.set_shell_view(ShellView::Catalog);
        app.set_input_mode(InputMode::Prompt);
        app
    }

    #[test]
    fn dependency_refresh_preserves_selection_and_belongs_to_the_empty_picker() {
        let mut app = catalog_app();
        app.move_catalog_cursor(1);
        let selected = app.catalog_cursor_module_id();
        let before = app
            .workbench_cache()
            .borrow()
            .executable_options_key(Vec::new());
        assert!(
            app.reduce_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE))
                .handled
        );
        assert_ne!(
            app.workbench_cache()
                .borrow()
                .executable_options_key(Vec::new()),
            before
        );
        assert_eq!(app.catalog_cursor_module_id(), selected);
        app.set_input("unfinished");
        let before = app
            .workbench_cache()
            .borrow()
            .executable_options_key(Vec::new());
        assert!(
            app.reduce_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE))
                .handled
        );
        assert_eq!(app.input(), "unfinishedr");
        assert_eq!(
            app.workbench_cache()
                .borrow()
                .executable_options_key(Vec::new()),
            before
        );
    }

    #[test]
    fn page_keys_move_the_picker_by_its_visible_rows() {
        let mut app = catalog_app();
        app.set_viewport(crate::app::TerminalViewport::new(110, 24));
        app.router.catalog_mut().expand();
        let page = app.catalog_visible_rows();
        let page_down = KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE);
        assert!(app.reduce_key(page_down).handled);
        assert_eq!(app.router.catalog().cursor(), page);
        let page_up = KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE);
        assert!(app.reduce_key(page_up).handled);
        assert_eq!(app.router.catalog().cursor(), 0);
        assert!(app.input().is_empty());
    }

    #[test]
    fn page_delta_matches_the_visible_row_budget() {
        assert_eq!(catalog_cursor_delta(KeyCode::PageDown, 7), Some(7));
        assert_eq!(catalog_cursor_delta(KeyCode::PageUp, 7), Some(-7));
        assert_eq!(catalog_cursor_delta(KeyCode::Up, 7), Some(-1));
        assert_eq!(catalog_cursor_delta(KeyCode::Home, 7), None);
    }

    #[test]
    fn empty_catalog_composer_gives_arrows_and_load_to_the_picker() {
        let mut app = catalog_app();
        let down = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
        assert!(app.reduce_key(down).handled);
        assert_eq!(app.catalog_cursor_module_id().as_deref(), Some("deep-map"));
        assert_eq!(app.input_mode(), InputMode::Prompt);
        let loaded = app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(loaded.handled && loaded.effects.is_empty());
        assert_eq!(app.input(), "run threat-model:build");
        assert_eq!(app.shell_view(), ShellView::Catalog);
        assert!(
            app.reduce_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL))
                .handled
        );
        assert!(app.input().is_empty());
        assert_eq!(app.catalog_cursor_module_id().as_deref(), Some("deep-map"));
    }

    #[test]
    fn catalog_draft_keeps_editor_keys_and_escape_clears_before_back() {
        let mut app = catalog_app();
        app.set_input("operator draft".to_string());
        assert!(
            app.reduce_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE))
                .handled
        );
        assert_eq!(app.input(), "operator drafte");
        assert_eq!(app.catalog_cursor_module_id().as_deref(), Some("quick-map"));
        assert!(
            app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
                .handled
        );
        assert_eq!(app.shell_view(), ShellView::Catalog);
        assert!(app.input().is_empty());
    }
}

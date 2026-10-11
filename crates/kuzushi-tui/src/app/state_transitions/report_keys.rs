use super::*;

impl ShellApp {
    pub(super) fn handle_report_modal_key(&mut self, key: KeyEvent) -> InputUpdate {
        if self.shell_view() != ShellView::Report || is_quit_chord(key) {
            return InputUpdate::ignored();
        }
        if self.router.report().editing_path() {
            self.edit_report_path(key);
            return InputUpdate::handled();
        }
        self.handle_report_navigation_key(key)
    }

    fn handle_report_navigation_key(&mut self, key: KeyEvent) -> InputUpdate {
        if self.input_mode() == InputMode::Navigate && report_choices_save_key(key) {
            return InputUpdate::handled_with_effects(vec![ShellEffect::PersistReportChoices]);
        }
        if self.input_mode() != InputMode::Navigate || !key.modifiers.is_empty() {
            return InputUpdate::ignored();
        }
        match key.code {
            KeyCode::Esc => self.close_report_to_origin(),
            KeyCode::PageUp => self.page_report(-1),
            KeyCode::PageDown => self.page_report(1),
            KeyCode::Home => self.scroll_to_top(),
            KeyCode::End => self.scroll_to_bottom(),
            _ => return self.handle_report_view_key(key, KeyModifierState::new(key)),
        }
        InputUpdate::handled()
    }

    fn handle_report_view_key(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> InputUpdate {
        if !modifiers.plain || !matches!(self.shell_view(), ShellView::Report) {
            return InputUpdate::ignored();
        }
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.router.report_mut().move_format(-1),
            KeyCode::Down | KeyCode::Char('j') => self.router.report_mut().move_format(1),
            KeyCode::Char('c') => self.router.report_mut().cycle_completeness(),
            KeyCode::Char('s') => self.router.report_mut().toggle_scope(),
            KeyCode::Char('p') => self.router.report_mut().toggle_provenance(),
            KeyCode::Char('e') => self.router.report_mut().set_editing_path(true),
            KeyCode::Char('q') => self.close_report_to_origin(),
            KeyCode::Enter => {
                return self.export_report_key();
            }
            KeyCode::Char('o') => {
                return InputUpdate::handled_with_effects(vec![
                    ShellEffect::RevealReportDestination,
                ]);
            }
            _ => return InputUpdate::ignored(),
        }
        InputUpdate::handled()
    }

    fn export_report_key(&mut self) -> InputUpdate {
        let campaign_id = match crate::ui_view_models::report_export_campaign(self) {
            Ok(campaign) => campaign,
            Err(error) => {
                self.router.report_mut().set_reveal_error(Some(error));
                return InputUpdate::handled();
            }
        };
        let route = self.router.report();
        let output = route.path_draft();
        if output.trim().is_empty() {
            self.router
                .report_mut()
                .set_reveal_error(Some("Enter a destination path.".into()));
            return InputUpdate::handled();
        }
        InputUpdate::handled_with_effects(vec![ShellEffect::ExportReport(ReportExport {
            format: route.format(),
            completeness: route.completeness(),
            output: PathBuf::from(output),
            target: self.target_owned(),
            campaign_id,
        })])
    }

    fn page_report(&mut self, direction: isize) {
        let offset = crate::renderer::report_offset_after_page(self, direction);
        self.router.default_scroll_mut().reset();
        self.router
            .default_scroll_mut()
            .scroll_down(offset.min(u16::MAX as usize) as u16);
    }

    fn edit_report_path(&mut self, key: KeyEvent) {
        if report_path_save_key(key) {
            self.router.report_mut().save_path_edit();
        } else if key.code == KeyCode::Esc && key.modifiers.is_empty() {
            self.router.report_mut().set_editing_path(false);
        } else {
            self.router.report_mut().edit_path_key(key);
        }
    }

    pub(super) fn capture_report_path_paste(&mut self, text: &str) -> bool {
        if self.shell_view() != ShellView::Report || !self.router.report().editing_path() {
            return false;
        }
        self.router.report_mut().insert_path_text(text);
        true
    }
}

fn report_path_save_key(key: KeyEvent) -> bool {
    (key.code == KeyCode::Enter && key.modifiers.is_empty())
        || (key.code == KeyCode::Char('s') && key.modifiers == KeyModifiers::CONTROL)
}

fn report_choices_save_key(key: KeyEvent) -> bool {
    key.code == KeyCode::Char('S')
        && matches!(key.modifiers, KeyModifiers::NONE | KeyModifiers::SHIFT)
}

#[cfg(test)]
mod tests;

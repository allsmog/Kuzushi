use super::*;

impl ShellApp {
    pub(super) fn toggle_lesson_selection(&mut self) {
        if self.runtime_state.lesson_write.is_some() {
            return;
        }
        let Some(reference) = self.selected_accepted_lesson_reference() else {
            return;
        };
        if let Err(error) = toggle_reference(&mut self.router.lessons.selected, reference) {
            self.router.lessons.notice = Some(error.into());
        }
    }

    fn selected_accepted_lesson_reference(&mut self) -> Option<LessonRef> {
        let record = self.selected_lesson()?;
        if record.state != LessonState::Accepted {
            self.router.lessons.notice =
                Some("Accept this lesson before selecting it for a context copy.".into());
            return None;
        }
        record.reference().ok()
    }

    pub(super) fn begin_lesson_context(&mut self) {
        if self.runtime_state.lesson_write.is_some() {
            return;
        }
        self.router.lessons.context_cursor = 1;
        self.router.lessons.context_selecting = true;
        self.router.lessons.context_confirm = None;
        self.router.lessons.notice = None;
        self.router.default_scroll_mut().set(0);
    }

    pub(super) fn handle_lesson_context_key(&mut self, key: KeyEvent) {
        if self.runtime_state.lesson_write.is_some() {
            return;
        }
        if self.router.lessons.context_confirm.is_some() {
            self.handle_lesson_context_confirm(key.code);
            return;
        }
        let catalog = crate::ui_view_models::study_context::context_catalog(self);
        match key.code {
            KeyCode::Esc => self.router.lessons.context_selecting = false,
            KeyCode::Up | KeyCode::Char('k') => {
                self.router.lessons.context_cursor =
                    self.router.lessons.context_cursor.saturating_sub(1).max(1)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.router.lessons.context_cursor = (self.router.lessons.context_cursor + 1)
                    .min(catalog.rows.len().saturating_sub(1))
            }
            KeyCode::Enter => {
                self.router.lessons.context_confirm = catalog
                    .rows
                    .get(self.router.lessons.context_cursor)
                    .and_then(|row| row.reference.clone())
            }
            _ => {}
        }
    }

    fn handle_lesson_context_confirm(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc => self.router.lessons.context_confirm = None,
            KeyCode::Enter => {
                let input = serde_json::json!({"threatModelRef":self.router.lessons.context_confirm,"lessons":self.router.lessons.selected});
                self.spawn_lesson_action("threat-model:reuse-lessons", input);
            }
            KeyCode::PageDown => self.router.default_scroll_mut().scroll_down(5),
            KeyCode::PageUp => {
                let offset = self.router.default_scroll().offset();
                self.router
                    .default_scroll_mut()
                    .set(offset.saturating_sub(5));
            }
            _ => {}
        }
    }

    pub(super) fn finish_lesson_context(&mut self, output: &serde_json::Value) {
        self.router.lessons.saved_context =
            serde_json::from_value(output["data"]["modelRef"].clone()).ok();
        self.router.lessons.context_selecting = false;
        self.router.lessons.context_confirm = None;
        self.router.lessons.notice=Some("Saved an inactive context copy. Inspect and select it in Scan context before approving work. The active context is unchanged.".into());
        if let Some(target) = self.target_owned() {
            self.workbench_cache()
                .borrow_mut()
                .invalidate_threat_model(&target);
        }
    }
}

fn remove_selected_lesson(selection: &mut Vec<LessonRef>, reference: &LessonRef) -> bool {
    let Some(index) = selection
        .iter()
        .position(|row| row.lesson_id == reference.lesson_id)
    else {
        return false;
    };
    selection.remove(index);
    true
}

fn toggle_reference(
    selection: &mut Vec<LessonRef>,
    reference: LessonRef,
) -> Result<(), &'static str> {
    if remove_selected_lesson(selection, &reference) {
        return Ok(());
    }
    if selection.len() == 8 {
        return Err("Select at most eight lessons. The previous selection is retained.");
    }
    selection.push(reference);
    Ok(())
}

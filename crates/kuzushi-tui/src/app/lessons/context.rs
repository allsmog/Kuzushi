use super::*;

impl ShellApp {
    pub(super) fn toggle_lesson_selection(&mut self) {
        if self.runtime_state.lesson_write.is_some() {
            return;
        }
        self.pin_current_lesson();
        let Some(selection) = self.selected_accepted_lesson() else {
            return;
        };
        if let Err(error) = toggle_reference(&mut self.router.lessons.selected, selection) {
            self.router.lessons.notice = Some(error.into());
        }
    }

    fn selected_accepted_lesson(&mut self) -> Option<SelectedLesson> {
        let record = self.selected_lesson()?;
        if record.state != LessonState::Accepted {
            self.router.lessons.notice =
                Some("Accept this lesson before selecting it for a context copy.".into());
            return None;
        }
        Some(SelectedLesson {
            reference: record.reference().ok()?,
            title: record.content.title,
        })
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
            KeyCode::Enter => self.choose_lesson_context_base(&catalog.rows),
            _ => {}
        }
    }

    fn choose_lesson_context_base(
        &mut self,
        rows: &[crate::ui_view_models::study_context::ContextRow],
    ) {
        self.router.lessons.context_confirm = rows
            .get(self.router.lessons.context_cursor)
            .and_then(|row| {
                Some(LessonContextBase {
                    reference: row.reference.clone()?,
                    label: row.label.clone(),
                })
            });
        self.router.default_scroll_mut().reset();
    }

    fn handle_lesson_context_confirm(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc => {
                self.router.lessons.context_confirm = None;
                self.router.default_scroll_mut().reset();
            }
            KeyCode::Enter => {
                let input = context_copy_input(
                    self.router.lessons.context_confirm.as_ref().unwrap(),
                    &self.router.lessons.selected,
                );
                self.spawn_lesson_action("threat-model:reuse-lessons", input);
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

fn remove_selected_lesson(selection: &mut Vec<SelectedLesson>, reference: &LessonRef) -> bool {
    let Some(index) = selection
        .iter()
        .position(|row| row.reference.lesson_id == reference.lesson_id)
    else {
        return false;
    };
    selection.remove(index);
    true
}

fn toggle_reference(
    selection: &mut Vec<SelectedLesson>,
    lesson: SelectedLesson,
) -> Result<(), &'static str> {
    if remove_selected_lesson(selection, &lesson.reference) {
        return Ok(());
    }
    if selection.len() == 8 {
        return Err("Select at most eight lessons. The previous selection is retained.");
    }
    selection.push(lesson);
    Ok(())
}

fn context_copy_input(base: &LessonContextBase, selected: &[SelectedLesson]) -> serde_json::Value {
    let lessons = selected
        .iter()
        .map(|lesson| &lesson.reference)
        .collect::<Vec<_>>();
    serde_json::json!({"threatModelRef":base.reference,"lessons":lessons})
}

#[cfg(test)]
mod tests;

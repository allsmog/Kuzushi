use super::*;

impl ShellApp {
    pub(super) fn begin_lesson_draft(&mut self, editing: bool) {
        if self.runtime_state.lesson_write.is_some() {
            return;
        }
        let Some(target) = self.target_owned() else {
            self.router.lessons.notice = Some("Select a target before drafting a lesson.".into());
            return;
        };
        let record = editing.then(|| self.selected_lesson()).flatten();
        if editing && record.is_none() {
            return;
        }
        let reference = record.as_ref().and_then(|record| record.reference().ok());
        let content = record.map(|record| record.content);
        let fields = lesson_fields(content);
        let finding_id = (!editing)
            .then_some(self.router.lessons.finding_id)
            .flatten();
        if !editing && finding_id.is_none() {
            self.router.lessons.notice=Some("Open a confirmed finding in Review, then use lessons to draft from that exact generation.".into());
            return;
        }
        self.router.lessons.form = Some(LessonForm {
            target,
            action: LessonFormAction::Draft {
                finding_id,
                reference,
            },
            fields,
            focused: 0,
            confirming: false,
        });
        self.router.lessons.form_visible = true;
        self.router.lessons.notice = None;
    }

    pub(super) fn begin_lesson_review(&mut self, state: LessonState) {
        if self.runtime_state.lesson_write.is_some() {
            return;
        }
        let Some(record) = self.selected_lesson() else {
            return;
        };
        let Some(target) = self.target_owned() else {
            return;
        };
        self.router.lessons.form = Some(LessonForm {
            target,
            action: LessonFormAction::Review { record, state },
            fields: Default::default(),
            focused: 0,
            confirming: false,
        });
        self.router.lessons.form_visible = true;
        self.router.lessons.notice = None;
    }

    pub(super) fn handle_lesson_form_key(&mut self, key: KeyEvent) {
        if self.runtime_state.lesson_write.is_some() {
            return;
        }
        let Some(form) = self.router.lessons.form.as_mut() else {
            return;
        };
        if form.confirming {
            self.handle_lesson_confirmation_key(key.code);
            return;
        }
        match key.code {
            KeyCode::Esc => self.router.lessons.form_visible = false,
            KeyCode::Tab => form.focused = (form.focused + 1) % form_field_count(form),
            KeyCode::BackTab => {
                form.focused = (form.focused + form_field_count(form) - 1) % form_field_count(form)
            }
            KeyCode::Enter if key.modifiers.contains(KeyModifiers::SHIFT) => {
                form.fields[form.focused].insert("\n")
            }
            KeyCode::Enter => self.review_lesson_form(),
            _ => {
                form.fields[form.focused].handle_key(key);
            }
        }
    }

    fn handle_lesson_confirmation_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc => self.router.lessons.form.as_mut().unwrap().confirming = false,
            KeyCode::Enter => self.submit_lesson_form(),
            KeyCode::PageDown => {
                let offset = self.router.default_scroll().offset();
                self.router
                    .default_scroll_mut()
                    .set(offset.saturating_add(5));
            }
            KeyCode::PageUp => {
                let offset = self.router.default_scroll().offset();
                self.router
                    .default_scroll_mut()
                    .set(offset.saturating_sub(5));
            }
            _ => {}
        }
    }

    fn review_lesson_form(&mut self) {
        let Some(form) = self.router.lessons.form.as_ref() else {
            return;
        };
        match lesson_form_input(form) {
            Ok(_) => {
                self.router.lessons.form.as_mut().unwrap().confirming = true;
                self.router.default_scroll_mut().set(0);
                self.router.lessons.notice = None;
            }
            Err(error) => self.router.lessons.notice = Some(error.to_string()),
        }
    }

    pub(crate) fn paste_lesson_field(&mut self, text: &str) -> bool {
        if self.shell_view() != ShellView::Lessons || !self.router.lessons.form_visible {
            return false;
        }
        let Some(form) = self.router.lessons.form.as_mut() else {
            return false;
        };
        if !form.confirming && self.runtime_state.lesson_write.is_none() {
            form.fields[form.focused].insert(text);
        }
        true
    }
}

fn lesson_fields(content: Option<LessonContent>) -> [FieldEditor; 4] {
    content
        .map(|content| {
            [
                content.title,
                content.text,
                content.applicability,
                content.limitations,
            ]
            .map(FieldEditor::new)
        })
        .unwrap_or_default()
}

fn form_field_count(form: &LessonForm) -> usize {
    match form.action {
        LessonFormAction::Draft { .. } => 4,
        LessonFormAction::Review { .. } => 1,
    }
}

pub(super) fn lesson_form_input(
    form: &LessonForm,
) -> anyhow::Result<(&'static str, serde_json::Value)> {
    match &form.action {
        LessonFormAction::Draft {
            finding_id,
            reference,
        } => draft_input(form, *finding_id, reference.as_ref()),
        LessonFormAction::Review { record, state } => {
            let note = form.fields[0].text().trim();
            anyhow::ensure!(
                !note.is_empty() && note.len() <= 4096,
                "A lesson decision needs a reason of 1 to 4096 bytes."
            );
            Ok((
                "findings:lesson-review",
                serde_json::json!({"lessonRef":record.reference()?,"state":state,"note":note}),
            ))
        }
    }
}

fn draft_input(
    form: &LessonForm,
    finding_id: Option<i64>,
    reference: Option<&LessonRef>,
) -> anyhow::Result<(&'static str, serde_json::Value)> {
    let content = LessonContent {
        title: form.fields[0].text().into(),
        text: form.fields[1].text().into(),
        applicability: form.fields[2].text().into(),
        limitations: form.fields[3].text().into(),
    };
    content.validate()?;
    let mut input = serde_json::json!({"content":content});
    if let Some(reference) = reference {
        input["lessonRef"] = serde_json::to_value(reference)?;
    } else {
        input["findingId"] = serde_json::json!(finding_id);
    }
    Ok(("findings:lesson-save", input))
}

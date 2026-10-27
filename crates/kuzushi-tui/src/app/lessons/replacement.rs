use super::*;

impl ShellApp {
    pub(super) fn request_lesson_form(&mut self, form: LessonForm) {
        self.pin_current_lesson();
        if self
            .router
            .lessons
            .form
            .as_ref()
            .is_some_and(LessonForm::has_unsaved_changes)
        {
            self.router.lessons.replacement_form = Some(form);
            self.router.lessons.form_visible = false;
            return;
        }
        self.show_lesson_form(form);
    }

    pub(super) fn handle_lesson_replacement_key(&mut self, key: KeyEvent) -> bool {
        if self.router.lessons.replacement_form.is_none() {
            return false;
        }
        match (key.code, key.modifiers) {
            (KeyCode::Enter | KeyCode::Char('d'), KeyModifiers::NONE) => {
                self.router.lessons.replacement_form = None;
                self.router.lessons.form_visible = self.router.lessons.form.is_some();
            }
            (KeyCode::Esc, KeyModifiers::NONE) => {
                self.router.lessons.replacement_form = None;
                self.router.lessons.notice =
                    Some("Unfinished form retained. Press d to resume.".into());
            }
            (KeyCode::Char('D'), KeyModifiers::NONE | KeyModifiers::SHIFT) => {
                let form = self.router.lessons.replacement_form.take().unwrap();
                self.show_lesson_form(form);
            }
            _ => {}
        }
        true
    }

    fn show_lesson_form(&mut self, form: LessonForm) {
        self.router.lessons.form = Some(form);
        self.router.lessons.replacement_form = None;
        self.router.lessons.form_visible = true;
        self.router.lessons.notice = None;
        self.router.default_scroll_mut().reset();
    }
}

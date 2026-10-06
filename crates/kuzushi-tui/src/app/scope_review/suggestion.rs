use super::*;

impl ShellApp {
    pub(super) fn open_scope_ai_priorities(&mut self) -> InputUpdate {
        let scope = self
            .scope_review()
            .and_then(|state| state.review.as_ref())
            .and_then(|review| review.record.draft.scopes.first())
            .cloned();
        let Some(scope) = scope else {
            self.scope_notice("Build the repository inventory before requesting AI suggestions.");
            return InputUpdate::handled();
        };
        let state = self.router.scope_review_mut().as_mut().unwrap();
        state.menu = None;
        state.form = Some(ScopeEditForm::for_scope(
            ScopeEditKind::AiPriorities,
            &scope,
        ));
        state.scroll = 0;
        state.notice = Some("One optional proposal over this repository inventory. F2 opens model and allowance review; nothing is sent yet. F3 chooses inherited Map context or explicit omission.".into());
        InputUpdate::handled()
    }

    pub(super) fn prepare_scope_ai_study(&mut self) -> InputUpdate {
        let Some(state) = self.scope_review() else {
            return InputUpdate::handled();
        };
        let Some((review, form)) = state.review.as_ref().zip(state.form.as_ref()) else {
            return InputUpdate::handled();
        };
        let reference = review.reference.clone();
        let priorities = form.fields[0].1.text().to_owned();
        let result = self.open_scope_proposal_study(reference, priorities, form.omit_context);
        if let Err(error) = result {
            self.scope_notice(format!("Scope proposal needs review: {error:#}. F3 may explicitly omit Map context. No model request was made."));
        }
        InputUpdate::handled()
    }
}

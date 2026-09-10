use super::*;

impl ShellApp {
    pub(crate) fn budget_editor_open(&self) -> bool {
        self.shell_view() == ShellView::Setup
            && self.router.setup().editor() == Some(SetupEditor::Budget)
    }

    pub(super) fn budget_editor_owns_key(&self, key: KeyEvent) -> bool {
        self.budget_editor_open() && !is_quit_chord(key)
    }

    pub(super) fn handle_setup_budget_key(&mut self, key: KeyEvent) -> InputUpdate {
        if budget_save_key(key) {
            return self.commit_setup_budget();
        }
        if key.code == KeyCode::Esc && key.modifiers.is_empty() {
            self.finish_budget_editor();
        } else {
            self.router.setup_mut().edit_budget_key(key);
        }
        InputUpdate::handled()
    }

    pub(super) fn capture_budget_paste(&mut self, text: &str) -> bool {
        if !self.budget_editor_open() {
            return false;
        }
        self.router.setup_mut().insert_budget_text(text);
        true
    }

    fn commit_setup_budget(&mut self) -> InputUpdate {
        let result = parse_setup_budget(
            self.router.setup().budget_draft(),
            self.config().operator.spend_hard_ceiling_usd,
        )
        .and_then(|value| self.validate_halted_budget(value));
        match result {
            Ok(value) => self.apply_setup_budget(value),
            Err(error) => self.router.setup_mut().set_budget_error(error),
        }
        InputUpdate::handled()
    }

    fn apply_setup_budget(&mut self, value: Option<f64>) {
        let previous = self.session().session_budget_usd();
        self.session_mut().set_session_budget_usd(value);
        self.advisory_mut().budget_halt = None;
        self.maybe_trigger_budget_halt();
        self.finish_budget_editor();
        let previous = previous
            .map(|amount| format!("${amount:?}"))
            .unwrap_or_else(|| "not set".into());
        let message = match value {
            Some(value) => format!("session budget set to ${value:?} (previous: {previous})"),
            None => "session budget unset".to_string(),
        };
        self.log("setup", message);
    }

    fn validate_halted_budget(&self, value: Option<f64>) -> Result<Option<f64>, String> {
        if !self.is_budget_halted() {
            return Ok(value);
        }
        if !self.session().cost_accounting_is_complete() {
            return Err("Resolve incomplete cost accounting before raising the cap".into());
        }
        let spent = self.session().session_cost_usd();
        if !value.is_some_and(|amount| amount > spent) {
            return Err(format!(
                "Approve a new cap above spent ${spent:?}; empty cannot clear this halt"
            ));
        }
        Ok(value)
    }

    fn finish_budget_editor(&mut self) {
        self.router.setup_mut().finish_editor();
        if let Some(origin) = self.router.setup_mut().take_budget_return_view() {
            self.set_shell_view(origin);
        }
    }
}

fn budget_save_key(key: KeyEvent) -> bool {
    (key.code == KeyCode::Enter && key.modifiers.is_empty())
        || (key.code == KeyCode::Char('s') && key.modifiers == KeyModifiers::CONTROL)
}

fn parse_setup_budget(draft: &str, ceiling: Option<f64>) -> Result<Option<f64>, String> {
    if draft.trim().is_empty() {
        return Ok(None);
    }
    let value = parse_positive_budget(draft)?;
    if let Some(ceiling) = ceiling.filter(|ceiling| value > *ceiling) {
        return Err(format!("Amount exceeds hard ceiling ${ceiling:?}"));
    }
    Ok(Some(value))
}

fn parse_positive_budget(draft: &str) -> Result<f64, String> {
    let value = draft
        .trim()
        .parse::<f64>()
        .map_err(|_| "Enter one positive USD amount, or empty to unset".to_string())?;
    if !value.is_finite() || value <= 0.0 {
        return Err("Amount must be finite and greater than zero".to_string());
    }
    Ok(value)
}

#[cfg(test)]
mod tests;

use super::*;

impl ShellApp {
    pub(crate) fn show_model_catalog(&mut self) {
        self.shell_view = ShellView::Config;
        self.sync_selected_model_index();
        self.log_model_catalog_status();
        self.log_model_catalog_choices();
        self.log_model_catalog_scope_hint();
    }

    fn log_model_catalog_status(&mut self) {
        let active = active_model_label(&self.config);
        let effort = self.session_thinking_level.as_deref().unwrap_or("default");
        self.log(
            "model",
            format!("active {active} / {effort}. Select with: model <n> [low|medium|high|xhigh]"),
        );
    }

    fn log_model_catalog_choices(&mut self) {
        for choice in MODEL_CHOICES {
            self.log("model", model_catalog_choice_line(choice));
        }
    }

    fn log_model_catalog_scope_hint(&mut self) {
        if let Some(hint) = model_catalog_scope_hint(&self.focused_module, &self.config) {
            self.log("model", hint);
        }
    }

    pub(crate) fn provider_label(&self) -> String {
        self.config
            .model
            .as_deref()
            .and_then(|model| model.split_once(':').map(|(provider, _)| provider))
            .filter(|provider| !provider.trim().is_empty())
            .unwrap_or("unconfigured")
            .to_string()
    }

    pub(crate) fn sync_selected_model_index(&mut self) {
        self.selected_model_index = preferred_model_choice_index(&self.config);
    }

    pub(crate) fn move_model_selection(&mut self, delta: isize) {
        let len = MODEL_CHOICES.len();
        if len == 0 {
            self.selected_model_index = 0;
            return;
        }
        let current = self.selected_model_index.min(len - 1) as isize;
        self.selected_model_index = (current + delta).rem_euclid(len as isize) as usize;
    }

    pub(crate) fn select_current_model_choice(&mut self) {
        let Some(choice) = MODEL_CHOICES.get(self.selected_model_index) else {
            self.log("error", "no model choices are available");
            return;
        };
        self.config.model = Some(choice.id.to_string());
        self.session_thinking_level = Some(choice.thinking_level.to_string());
        self.shell_view = ShellView::Config;
        self.log(
            "model",
            format!(
                "{} / {} selected via onboarding (session only; no fallback model will be selected)",
                choice.id, choice.thinking_level
            ),
        );
    }
}

fn active_model_label(config: &V2Config) -> String {
    config
        .model
        .clone()
        .unwrap_or_else(|| "unconfigured".to_string())
}

fn model_catalog_choice_line(choice: &ModelChoice) -> String {
    format!(
        "{}. {}  {}  {}  auth {}",
        choice.index, choice.id, choice.thinking_level, choice.label, choice.auth
    )
}

fn model_catalog_scope_hint(
    focused_module: &Option<String>,
    config: &V2Config,
) -> Option<&'static str> {
    focused_module.as_ref()?;
    Some(if config.model.is_none() {
        "focused module detected, but no global model yet — model <n> sets the global model so `ask` works. Use `model module <n>` to scope per-module."
    } else {
        "focused module detected: model <n> sets this module; use `model global <n>` for global ask/defaults."
    })
}

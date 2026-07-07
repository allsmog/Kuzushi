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
        let active = active_model_label(self.config());
        let effort = self.session_thinking_level().unwrap_or("default");
        self.log(
            "model",
            format!("active {active} / {effort}. Select with: model <n> [low|medium|high|xhigh]"),
        );
    }

    fn log_model_catalog_choices(&mut self) {
        for choice in visible_model_choices(self.config().model.as_deref()) {
            self.log("model", model_catalog_choice_line(choice));
        }
    }

    fn log_model_catalog_scope_hint(&mut self) {
        if let Some(hint) = model_catalog_scope_hint(self.focused_module(), self.config()) {
            self.log("model", hint);
        }
    }

    pub(crate) fn provider_label(&self) -> String {
        self.config()
            .model
            .as_deref()
            .and_then(|model| model.split_once(':').map(|(provider, _)| provider))
            .map(display_model_provider)
            .filter(|provider| !provider.trim().is_empty())
            .unwrap_or("— none active (press Enter on a row)")
            .to_string()
    }

    pub(crate) fn sync_selected_model_index(&mut self) {
        let selected_index = preferred_model_choice_index(self.config());
        self.router
            .model_catalog_mut()
            .set_selected_index(selected_index);
    }

    pub(crate) fn move_model_selection(&mut self, delta: isize) {
        // Step only through the rows the Config view actually shows. Cycling the
        // full MODEL_CHOICES set could land the route cursor on a hidden
        // row (the non-primary OpenAI entry), which the renderer collapses to the
        // first visible row — so the highlight and the Enter-selected model would
        // disagree. Navigating the visible set keeps them in lockstep.
        let visible = visible_model_choice_indexes(self.config().model.as_deref());
        self.router
            .model_catalog_mut()
            .move_selection(&visible, delta);
    }

    pub(crate) fn select_current_model_choice(&mut self) -> Vec<ShellEffect> {
        let Some(choice) = MODEL_CHOICES.get(self.router.model_catalog().selected_index()) else {
            self.log("error", "no model choices are available");
            return Vec::new();
        };
        self.config_mut().model = Some(choice.id.to_string());
        self.set_session_thinking_level(Some(choice.thinking_level.to_string()));
        self.shell_view = ShellView::Config;
        self.log(
            "model",
            format!(
                "{} / {} selected (no fallback model) — showing config, Esc to go back",
                model_choice_display_selector(choice),
                choice.thinking_level
            ),
        );
        vec![crate::app::global_model_selection_persist_effect(
            choice.id,
            Some(choice.thinking_level),
        )]
    }
}

fn active_model_label(config: &V2Config) -> String {
    config
        .model
        .as_deref()
        .map(display_model_selector)
        .unwrap_or_else(|| "unconfigured".to_string())
}

fn model_catalog_choice_line(choice: &ModelChoice) -> String {
    format!(
        "{}. {}  {}  {}  auth {}",
        choice.index,
        model_choice_display_selector(choice),
        choice.thinking_level,
        choice.label,
        choice.auth
    )
}

fn model_catalog_scope_hint(
    focused_module: Option<&str>,
    config: &V2Config,
) -> Option<&'static str> {
    focused_module?;
    Some(if config.model.is_none() {
        "focused module detected, but no global model yet — model <n> sets the global model so `ask` works. Use `model module <n>` to scope per-module."
    } else {
        "focused module detected: model <n> sets this module; use `model global <n>` for global ask/defaults."
    })
}

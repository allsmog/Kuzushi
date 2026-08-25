use super::*;

impl ShellApp {
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
        let visible = visible_model_choice_indexes(self.config());
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
        self.set_shell_view(ShellView::Config);
        self.log(
            "model",
            format!(
                "{} / {} selected (no fallback model) — showing config; type `back` to return",
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

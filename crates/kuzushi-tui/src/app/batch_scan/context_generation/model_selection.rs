use super::*;

impl ShellApp {
    pub(crate) fn refresh_context_generation_model(&mut self) {
        let model = self.config().model.clone();
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return;
        };
        let Some(generation) = config
            .context_generation
            .as_mut()
            .filter(|generation| generation.allows_model_choice())
        else {
            return;
        };
        if generation.context_input["model"].as_str() == model.as_deref() {
            return;
        }
        generation.bind_completed_scope_reference();
        generation.clear_model_plan();
        update_selected_model(&mut generation.context_input, model);
        config.notice = Some("Model changed. Prepare and approve a new plan; previous spending and saved results remain recorded.".into());
    }
}

impl StudyContextGeneration {
    fn clear_model_plan(&mut self) {
        self.receipt = None;
        self.campaign_id = None;
        self.generated = None;
        self.generated_scopes = None;
        self.generated_lesson = None;
        self.map_attempt_id = None;
        self.result_error = None;
        self.scroll = 0;
        self.show_options = false;
        self.show_rejected = false;
        self.options = Default::default();
    }
}

fn update_selected_model(input: &mut Value, model: Option<String>) {
    match model {
        Some(model) => input["model"] = json!(model),
        None => {
            input.as_object_mut().unwrap().remove("model");
        }
    }
}

use super::*;

impl StudyContextGeneration {
    pub(crate) fn supports_brief_guidance(&self) -> bool {
        matches!(
            self.generation_tool.as_deref(),
            None | Some("threat-model:build")
        )
    }
}

impl ShellApp {
    pub(crate) fn capture_bound_brief_paste(&self) -> bool {
        self.context_generation()
            .is_some_and(|generation| generation.show_brief_guidance)
    }
    pub(super) fn context_brief_key(&mut self, code: KeyCode) -> Option<InputUpdate> {
        let generation = self.context_generation()?;
        if generation.show_brief_guidance {
            self.bound_brief_preview_key(code);
            return Some(InputUpdate::handled());
        }
        if !generation.supports_brief_guidance() {
            return None;
        }
        match code {
            KeyCode::Char('g') => {
                self.toggle_brief_guidance();
                Some(InputUpdate::handled())
            }
            KeyCode::Char('b') => Some(self.inspect_generation_brief()),
            _ => None,
        }
    }

    fn bound_brief_preview_key(&mut self, code: KeyCode) {
        if code == KeyCode::Esc {
            let generation = self.context_generation_mut().unwrap();
            generation.show_brief_guidance = false;
            generation.scroll = generation.brief_origin_scroll;
        } else {
            self.scroll_context_generation(code);
        }
    }

    fn context_generation_mut(&mut self) -> Option<&mut StudyContextGeneration> {
        self.router
            .campaign_mut()
            .batch_scan_config
            .as_mut()?
            .context_generation
            .as_mut()
    }

    fn toggle_brief_guidance(&mut self) {
        let config = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap();
        let generation = config.context_generation.as_mut().unwrap();
        if generation.receipt.is_some() {
            config.notice = Some("Goal guidance is frozen with this plan. n starts a new draft for separate approval.".into());
            return;
        }
        if config.study.brief.is_none() {
            config.notice = Some(
                "Choose and save an exact goal revision first. b opens its editor; no work starts."
                    .into(),
            );
            return;
        }
        generation.use_brief_guidance = !generation.use_brief_guidance;
        generation.scroll = 0;
        config.notice = Some("Goal guidance choice changed. Review the exact text and model before approving this context plan. No model request made.".into());
    }

    fn inspect_generation_brief(&mut self) -> InputUpdate {
        if let Some(receipt) = self
            .context_generation()
            .and_then(|generation| generation.receipt.as_ref())
        {
            if receipt.brief_guidance.is_some() {
                let generation = self.context_generation_mut().unwrap();
                generation.show_brief_guidance = true;
                generation.brief_origin_scroll = generation.scroll;
                generation.scroll = 0;
            } else {
                self.set_batch_config_notice("This plan supplies no operator goal to the model. n starts a new draft with an explicit guidance choice.");
            }
            return InputUpdate::handled();
        }
        self.open_investigation_brief()
    }
}

pub(super) fn fresh_input(mut input: Value) -> Value {
    if let Some(object) = input.as_object_mut() {
        object.remove("operatorBriefRef");
    }
    input
}

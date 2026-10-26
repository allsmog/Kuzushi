use super::*;

impl ShellApp {
    pub(super) fn inspect_rejected_context(&mut self) {
        let Some(config) = self.router.campaign().batch_scan_config.as_ref() else {
            return;
        };
        let Some(receipt) = config
            .context_generation
            .as_ref()
            .and_then(|generation| generation.receipt.as_ref())
        else {
            return;
        };
        let outcome = receipt
            .rejected_output(&config.target)
            .and_then(|output| output.context("No rejected output was retained for this job"))
            .map_err(|error| error.to_string());
        if let Some(generation) = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .and_then(|config| config.context_generation.as_mut())
        {
            generation.rejected_output = Some(outcome);
            generation.show_rejected = true;
            std::mem::swap(&mut generation.scroll, &mut generation.rejected_scroll);
        }
    }

    pub(super) fn handle_rejected_context_key(&mut self, code: KeyCode) -> InputUpdate {
        if code == KeyCode::Char('e')
            && self
                .context_generation()
                .is_some_and(|g| g.is_scope_proposal())
        {
            return self.open_scope_correction();
        }
        if matches!(code, KeyCode::Esc | KeyCode::Char('d')) {
            if let Some(generation) = self
                .router
                .campaign_mut()
                .batch_scan_config
                .as_mut()
                .and_then(|config| config.context_generation.as_mut())
            {
                generation.show_rejected = false;
                std::mem::swap(&mut generation.scroll, &mut generation.rejected_scroll);
            }
        } else {
            self.scroll_context_generation(code);
        }
        InputUpdate::handled()
    }

    pub(super) fn toggle_rejected_output_retention(&mut self) {
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return;
        };
        let Some(generation) = config.context_generation.as_mut() else {
            return;
        };
        if generation.receipt.is_some() {
            config.notice = Some("Rejected-output handling is frozen in this plan. n opens a separately approved draft to change it.".into());
            return;
        }
        let enabled = generation.context_input["saveRejectedOutput"]
            .as_bool()
            .unwrap_or(true);
        generation.context_input["saveRejectedOutput"] = json!(!enabled);
        generation.scroll = 0;
    }
}

use crate::app::ShellApp;

impl ShellApp {
    pub(crate) fn study_preparation_failed(&mut self, tool: &str, message: &str) {
        if self.cache_review_planning_failure(tool, message) {
            return;
        }
        if tool == "campaign:context-study" {
            self.record_context_preparation_failure(message);
            return;
        }
        if tool != "campaign:study" {
            return;
        }
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return;
        };
        config.study.preparation_error = Some(message.to_owned());
        config.detail_scroll = 0;
        config.detail_reader_scroll = config.detail_reader_scroll.map(|_| 0);
    }

    fn record_context_preparation_failure(&mut self, message: &str) {
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return;
        };
        let Some(generation) = config.context_generation.as_mut() else {
            return;
        };
        generation.scroll = 0;
        config.notice = Some(format!("Plan preparation blocked: {message}. Your question and options are kept. No model request started; review the inputs before preparing again."));
    }

    pub(crate) fn study_notice_captures_escape(&self) -> bool {
        self.notice_captures_escape()
            || self
                .router
                .campaign()
                .batch_scan_config
                .as_ref()
                .is_some_and(|config| config.study.preparation_error.is_some())
    }

    pub(super) fn clear_study_preparation_error(&mut self) {
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            config.study.preparation_error = None;
        }
    }

    pub(crate) fn study_failure_next_step(&self, tool: &str) -> Option<&'static str> {
        if tool != "campaign:study" {
            return None;
        }
        self.router.campaign().batch_scan_config.as_ref()?;
        Some("Review Discovery engines and Source and context, then L prepares a new draft. Your settings and spending account are kept.")
    }
}

#[cfg(test)]
mod tests;

use crate::app::ShellApp;

impl ShellApp {
    pub(crate) fn refresh_study_usage_from_cache(&mut self) {
        let Some(config) = &self.router.campaign().batch_scan_config else {
            return;
        };
        let (catalogue, selected) = {
            let cache = self.workbench_cache().borrow();
            (
                cache.cached_study_usage_catalogue(&config.target),
                config
                    .prior_run_id
                    .as_ref()
                    .map(|id| cache.cached_study_usage_run(&config.target, id)),
            )
        };
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return;
        };
        config.apply_usage_catalogue(catalogue);
        if let Some(selected) = selected {
            config.apply_selected_usage(selected);
        }
    }
}

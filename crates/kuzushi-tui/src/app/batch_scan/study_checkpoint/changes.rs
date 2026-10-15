use super::*;

impl ShellApp {
    pub(in crate::app::batch_scan) fn initialize_study_checkpoint_baseline(&mut self) {
        let config = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap();
        config.checkpoint_initial = Some(projection::capture(config, raw_input(config)));
    }

    pub(super) fn unfinished_study_choices(&self, config: &BatchScanConfig) -> bool {
        if !discovery_study(config) {
            return false;
        }
        if config.study.matrix.has_unsaved_changes() {
            return true;
        }
        self.unprepared_settings_changed(config) || self.unsaved_study_brief(config).is_some()
    }

    fn unprepared_settings_changed(&self, config: &BatchScanConfig) -> bool {
        if config.study.plan_identity().is_some() {
            return prepared_resource_choices(config);
        }
        if selected_scopes(config) {
            return true;
        }
        let Some(initial) = &config.checkpoint_initial else {
            return false;
        };
        navigation_free(projection::capture(config, raw_input(config)))
            != navigation_free(initial.clone())
    }

    pub(super) fn capture_study_checkpoint(
        &self,
        config: &BatchScanConfig,
    ) -> anyhow::Result<StudyCheckpointSnapshot> {
        let input = super::super::launch::configured_scan_input(self, config)?;
        let mut snapshot = projection::capture(config, input);
        snapshot.brief_draft = self.unsaved_study_brief(config);
        Ok(snapshot)
    }
}

fn prepared_resource_choices(config: &BatchScanConfig) -> bool {
    config.number_edit.is_some() || (!config.study.approved() && resource_values_selected(config))
}

fn resource_values_selected(config: &BatchScanConfig) -> bool {
    config.study.max_provider_calls.is_some()
        || config.study.protected_review_calls.is_some()
        || config.study.max_job_attempts != 1
}

fn selected_scopes(config: &BatchScanConfig) -> bool {
    config.study.scope_draft.is_some()
        || config
            .study
            .scan_input
            .as_ref()
            .is_some_and(|input| input.get("scanScopeRef").is_some())
}

pub(super) fn discovery_study(config: &BatchScanConfig) -> bool {
    config.context_generation.is_none()
        && config.review_plan.is_none()
        && config.study.review_receipt.is_none()
}

fn raw_input(config: &BatchScanConfig) -> serde_json::Value {
    config
        .study
        .scan_input
        .clone()
        .unwrap_or(serde_json::Value::Null)
}

fn navigation_free(mut snapshot: StudyCheckpointSnapshot) -> StudyCheckpointSnapshot {
    snapshot.matrix_cursor = 0;
    snapshot.matrix_open = false;
    snapshot.form_cursor = 0;
    snapshot.detail_scroll = 0;
    snapshot.origin_hashes.clear();
    snapshot
}

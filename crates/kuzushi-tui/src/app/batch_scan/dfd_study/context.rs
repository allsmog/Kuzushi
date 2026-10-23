use super::super::context_generation::StudyContextGeneration;
use super::*;
use serde_json::json;

impl ShellApp {
    pub(in crate::app::batch_scan) fn recover_dfd_context_origin(
        &mut self,
        config: &mut BatchScanConfig,
        id: &str,
    ) {
        let matches = self
            .router
            .campaign()
            .dfd_study_return
            .as_ref()
            .is_some_and(|saved| {
                saved
                    .context_generation
                    .as_ref()
                    .and_then(|generation| generation.receipt.as_ref())
                    .is_some_and(|receipt| receipt.campaign_id == id)
            });
        if !matches {
            return;
        }
        let Some(mut saved) = self.router.campaign_mut().dfd_study_return.take() else {
            return;
        };
        config.dfd_origin = saved.dfd_origin.take();
        config.origin = saved.origin.take();
    }

    pub(crate) fn open_selected_dfd_context_study(&mut self) -> InputUpdate {
        let model = crate::ui_view_models::dfd_model(self);
        self.open_dfd_context_study(
            &model,
            self.router.scene().dfd_selection(),
            self.router
                .scene()
                .dfd_focused()
                .then_some(self.router.scene().dfd_context_selection()),
            crate::ui_view_models::displayed_threat_model_ref(self),
        )
    }

    pub(in crate::app::batch_scan) fn open_dfd_context_study(
        &mut self,
        model: &DfdModel,
        selection: usize,
        context_row: Option<usize>,
        reference: Result<ThreatModelRef, String>,
    ) -> InputUpdate {
        match self.prepare_dfd_context_study(model, selection, context_row, reference) {
            Ok(config) => self.install_dfd_study(config),
            Err(error) => self.refuse_dfd_study(format!("{error:#}")),
        }
        InputUpdate::handled()
    }

    fn prepare_dfd_context_study(
        &self,
        model: &DfdModel,
        selection: usize,
        context_row: Option<usize>,
        reference: Result<ThreatModelRef, String>,
    ) -> anyhow::Result<BatchScanConfig> {
        let (mut config, source, reference) =
            self.prepare_dfd_config(model, selection, context_row, reference)?;
        config.context_generation = Some(StudyContextGeneration {
            generation_tool: Some("threat-model:build".into()),
            context_input: json!({"sourcePaths":source.paths,"inheritedContextRef":reference,
                "maxSourceBytes":65536,"contextLimit":200,"maxOutputTokens":8192}),
            ..Default::default()
        });
        config.notice = Some(format!(
            "Context for {}. Back returns to the diagram.",
            source.label
        ));
        Ok(config)
    }
}

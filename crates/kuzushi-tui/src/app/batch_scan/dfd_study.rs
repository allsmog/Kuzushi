//! Explicit diagram handoff into the existing finite study planner.
use super::{BatchScanConfig, BatchScanConfigRow};
use crate::app::state_transitions::InputUpdate;
use crate::app::{ShellApp, ShellView};
use crate::ui_view_models::DfdModel;
use kuzushi_core::ThreatModelRef;
use serde_json::Value;
mod accounting;
mod navigation;
mod selection;
pub(super) use navigation::DfdStudyOrigin;
use selection::DfdScanSelection;

impl ShellApp {
    pub(crate) fn open_selected_dfd_study(&mut self) -> InputUpdate {
        let model = crate::ui_view_models::dfd_model(self);
        let reference = crate::ui_view_models::displayed_threat_model_ref(self);
        self.open_dfd_scan_study(
            &model,
            self.router.scene().dfd_selection(),
            self.router
                .scene()
                .dfd_focused()
                .then_some(self.router.scene().dfd_context_selection()),
            reference,
        )
    }

    pub(crate) fn open_dfd_scan_study(
        &mut self,
        model: &DfdModel,
        selection: usize,
        context_row: Option<usize>,
        reference: Result<ThreatModelRef, String>,
    ) -> InputUpdate {
        match self.prepare_dfd_study(model, selection, context_row, reference) {
            Ok(config) => {
                self.install_dfd_study(config);
                self.refresh_batch_worker_resolution();
            }
            Err(error) => self.refuse_dfd_study(format!("{error:#}")),
        }
        InputUpdate::handled()
    }

    fn prepare_dfd_study(
        &self,
        model: &DfdModel,
        selection: usize,
        context_row: Option<usize>,
        reference: Result<ThreatModelRef, String>,
    ) -> anyhow::Result<BatchScanConfig> {
        anyhow::ensure!(
            !self.has_running_work(),
            "Wait for active work. The diagram selection is retained."
        );
        anyhow::ensure!(self.router.campaign().dfd_study_return.is_none(), "Return from the existing diagram investigation before opening another. Its draft is retained.");
        let target = self
            .target_owned()
            .ok_or_else(|| anyhow::anyhow!("Select a repository first."))?;
        let reference = reference.map_err(anyhow::Error::msg)?;
        let source = DfdScanSelection::from_model(&target, model, selection, context_row)?;
        let mut config = BatchScanConfig::load(&target, None);
        self.inherit_dfd_study_accounting(&mut config)?;
        config.study.ensure_accounting_ready()?;
        config.study.scan_input = Some(self.dfd_study_input(&reference, &source)?);
        config.cursor = BatchScanConfigRow::ALL
            .iter()
            .position(|row| *row == BatchScanConfigRow::Context)
            .unwrap();
        config.notice = Some(dfd_study_notice(&source, &reference));
        Ok(config)
    }

    fn dfd_study_input(
        &self,
        reference: &ThreatModelRef,
        source: &DfdScanSelection,
    ) -> anyhow::Result<Value> {
        let mut input = match self
            .study_context_picker()
            .filter(|picker| picker.diagram_visible)
        {
            Some(picker) => picker.scan_input.clone(),
            None => super::launch::preview_scan_input_for_context(self, reference)?,
        };
        let object = input
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("Study source options are unavailable."))?;
        for key in ["scanScopeRef", "scanContextRef", "threatModelDigestRef"] {
            object.remove(key);
        }
        input["paths"] = serde_json::json!(source.paths);
        input["threatModelRef"] = serde_json::json!(reference);
        Ok(crate::app::force_shell_discovery_only_sast_input(
            "sast:scan",
            input,
        ))
    }

    fn inherit_dfd_study_accounting(&self, config: &mut BatchScanConfig) -> anyhow::Result<()> {
        let Some(parent) = self.router.campaign().batch_scan_config.as_ref() else {
            super::map_allowance::restore_diagram_map_allowance(
                config,
                crate::ui_view_models::map_context_run_refs(self).as_deref(),
            );
            return Ok(());
        };
        anyhow::ensure!(parent.dfd_origin.is_none(), "Return to the original diagram before planning another investigation. No nested work added.");
        anyhow::ensure!(
            std::fs::canonicalize(&parent.target)? == std::fs::canonicalize(&config.target)?,
            "The open study belongs to another target. Return to it before planning new work."
        );
        parent.study.ensure_accounting_ready()?;
        config.study.investigation_id = parent.study.investigation_id.clone();
        config.study.allowance = parent.study.allowance.clone();
        config.study.max_provider_calls = parent.study.max_provider_calls;
        config.study.protected_review_calls = parent.study.protected_review_calls;
        config.study.baseline_allowance_pending = parent.study.baseline_allowance_pending;
        config.study.brief = parent.study.brief.clone();
        Ok(())
    }

    fn refuse_dfd_study(&mut self, message: String) {
        if let Some(diagram) = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .and_then(|config| config.context_picker.as_mut())
            .and_then(|picker| picker.diagram.as_mut())
        {
            diagram.notice = Some(message);
            return;
        }
        self.set_warn_notice("DFD scan plan", message);
    }
}

fn dfd_study_notice(source: &DfdScanSelection, reference: &ThreatModelRef) -> String {
    let mut lines = vec![
        format!("Plan from DFD: {}", source.label),
        "Three passes, one worker, one attempt per job.".into(),
        format!("Context {} / {}", reference.model_id, reference.revision_id),
        format!("{} exact source paths (quoted):", source.paths.len()),
    ];
    lines.extend(
        source
            .paths
            .iter()
            .map(|path| format!("  {}", serde_json::json!(path))),
    );
    lines.push("Review engines and allowance before approval. No jobs started. Back returns to the diagram.".into());
    lines.join("\n")
}

#[cfg(test)]
mod tests;

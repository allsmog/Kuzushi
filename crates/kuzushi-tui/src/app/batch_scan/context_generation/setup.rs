//! Setup enters the same durable context study as the Scan context picker.
use super::*;
use crate::app::{PlanningTaskId, ShellView};

impl ShellApp {
    pub(crate) fn review_setup_allowance(&mut self) -> Option<InputUpdate> {
        let picker = self.engagement.planning_picker();
        let plan =
            crate::app::build_execution_plan(picker.tasks(), picker.selected(), picker.rebuild());
        self.review_model_backed_map(&plan)
    }

    pub(crate) fn review_model_backed_map(
        &mut self,
        plan: &[PlanningTaskId],
    ) -> Option<InputUpdate> {
        if plan
            .iter()
            .any(|task| task.phase() != kuzushi_core::WorkflowPhase::Map)
            || !plan
                .iter()
                .any(|task| self.planning_task_model_backed(*task))
        {
            return None;
        }
        if let Err(error) = self.open_setup_context_study(plan) {
            self.set_warn_notice(
                "planning",
                format!("Map plan needs review: {error:#}. No jobs started."),
            );
        }
        Some(InputUpdate::handled())
    }

    fn open_setup_context_study(&mut self, plan: &[PlanningTaskId]) -> Result<()> {
        let target = self.target_owned().context("Select a repository first")?;
        let (context_input, preparation_jobs) = self.setup_context_inputs(plan)?;
        let mut config = self
            .router
            .campaign()
            .setup_context_study
            .clone()
            .filter(|config| config.target == target)
            .unwrap_or_else(|| BatchScanConfig::load_for_map_study(&target));
        refresh_saved_study(&mut config, &target)?;
        config.study.ensure_accounting_ready()?;
        configure_generation(&mut config, context_input, preparation_jobs);
        config.notice = config.context_generation.as_ref()
            .filter(|generation| generation.receipt.is_none())
            .map(|_| "Review the selected Map work and set its shared allowance. Preparing a draft makes no model request. Esc returns to your unchanged Map selection.".into());
        self.show_study_form(config);
        Ok(())
    }

    fn setup_context_inputs(&self, plan: &[PlanningTaskId]) -> Result<(Value, Value)> {
        anyhow::ensure!(
            plan.contains(&PlanningTaskId::BuildThreatModel),
            "this Map combination has no supported fixed-plan executor yet"
        );
        let mut preparation = Vec::new();
        for task in plan
            .iter()
            .filter(|task| **task != PlanningTaskId::BuildThreatModel)
        {
            anyhow::ensure!(matches!(task, PlanningTaskId::GatherRepoContext | PlanningTaskId::MapEntryPoints),
                "{} cannot yet join an approved context study; keep it as separate deterministic Map work", task.label());
            preparation.push(json!({"tool":task.tool_name(),"input":self.resolved_input_for_planning_task(*task)?}));
        }
        Ok((self.selected_context_options()?, json!(preparation)))
    }

    fn selected_context_options(&self) -> Result<Value> {
        let task = PlanningTaskId::BuildThreatModel;
        let explicit =
            crate::app::planning_task_explicit_input(task, self.engagement.option_overrides());
        // Merge stored operator settings without materializing legacy defaults.
        let mut input = serde_json::to_value(
            self.option_store()
                .effective_stored_values(task.tool_name()),
        )?;
        input
            .as_object_mut()
            .unwrap()
            .extend(explicit.as_object().unwrap().clone());
        Ok(input)
    }

    pub(super) fn retain_setup_context_study(&mut self) -> bool {
        let Some(config) = self.router.campaign().batch_scan_config.as_ref() else {
            return false;
        };
        if !config
            .origin
            .as_ref()
            .is_some_and(|origin| origin.view == ShellView::Setup)
        {
            return false;
        }
        self.router.campaign_mut().setup_context_study = Some(config.clone());
        true
    }
}

fn configure_generation(
    config: &mut BatchScanConfig,
    context_input: Value,
    preparation_jobs: Value,
) {
    let same = config
        .context_generation
        .as_ref()
        .is_some_and(|generation| {
            generation.context_input == context_input
                && generation.preparation_jobs == preparation_jobs
        });
    if same {
        return;
    }
    config.context_generation = Some(StudyContextGeneration {
        context_input,
        preparation_jobs,
        ..Default::default()
    });
}

fn refresh_saved_study(config: &mut BatchScanConfig, target: &std::path::Path) -> Result<()> {
    let Some(generation) = config.context_generation.as_mut() else {
        return Ok(());
    };
    if let Some(receipt) = &generation.receipt {
        config.study.allowance = receipt.load_allowance(target)?;
    }
    generation.refresh_result(target);
    Ok(())
}

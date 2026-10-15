use super::{BatchScanConfig, StudyContextGeneration};
use crate::app::{state_transitions::InputUpdate, ShellApp, ShellView};
use anyhow::{Context, Result};
use serde_json::json;

impl ShellApp {
    pub(crate) fn cache_lesson_planning_failure(&mut self, tool: &str, error: &str) {
        if !matches!(
            tool,
            "campaign:context-study" | "campaign:approve-allowance"
        ) {
            return;
        }
        let Some(config) = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .filter(|config| {
                config
                    .context_generation
                    .as_ref()
                    .is_some_and(|generation| generation.is_lesson())
            })
        else {
            return;
        };
        config.notice=Some(format!("Lesson preparation or approval failed: {error}. No model request started. Inspect Activity, then revise this draft before retrying."));
    }

    pub(crate) fn plan_lesson_generation(&mut self) {
        if let Err(error) = self.open_lesson_study() {
            self.router.lessons.notice = Some(format!("Lesson draft needs preparation: {error:#}"));
        }
    }

    fn open_lesson_study(&mut self) -> Result<()> {
        anyhow::ensure!(
            !self.has_running_work(),
            "Wait for active work before preparing another lesson draft"
        );
        let target = self.target_owned().context("Select a repository first")?;
        let id = self
            .router
            .lessons
            .finding_id
            .context("Open a confirmed finding in Review before planning a lesson")?;
        let mut config = self
            .router
            .lessons
            .generation_study
            .as_deref()
            .cloned()
            .or_else(|| self.router.campaign().batch_scan_config.clone())
            .filter(|config| config.target == target)
            .unwrap_or_else(|| BatchScanConfig::load_for_map_study(&target));
        config.study.ensure_accounting_ready()?;
        config.context_picker = None;
        config.context_generation = Some(StudyContextGeneration {
            generation_tool: Some("findings:lesson-generate".into()),
            context_input: json!({"findingId":id}),
            ..Default::default()
        });
        config.notice=Some("Plan one defensive lesson draft from the recorded observation. Generation uses Learning calls from the investigation allowance. Human review and context reuse remain separate. No model request has started.".into());
        self.show_study_form(config);
        Ok(())
    }

    pub(super) fn inspect_generated_lesson(&mut self) -> InputUpdate {
        let Some(reference) = self
            .context_generation()
            .and_then(|generation| generation.generated_lesson.clone())
        else {
            return InputUpdate::handled();
        };
        self.retain_lesson_study();
        self.close_batch_config();
        self.set_shell_view(ShellView::Lessons);
        self.set_input_mode(crate::InputMode::Navigate);
        self.refresh_lessons();
        self.router.lessons.cursor = 0;
        self.router.lessons.pinned_id = Some(reference.lesson_id.clone());
        self.router.lessons.offset = 0;
        self.router.lessons.notice=Some(format!("Generation produced {} v{}. The current revision and review decision are shown above. Inspect source limits before reuse. No finding verdict or context selection changed.",reference.lesson_id,reference.revision));
        InputUpdate::handled()
    }

    pub(super) fn retain_lesson_study(&mut self) {
        let Some(config) = self
            .router
            .campaign()
            .batch_scan_config
            .as_ref()
            .filter(|config| {
                config
                    .context_generation
                    .as_ref()
                    .is_some_and(|generation| generation.is_lesson())
            })
        else {
            return;
        };
        self.router.lessons.generation_study = Some(Box::new(config.clone()));
    }
}

impl StudyContextGeneration {
    pub(super) fn lesson_action(&self, config: &BatchScanConfig) -> &'static str {
        match (
            self.result_error.is_some(),
            self.generated_lesson.is_some(),
            self.receipt.is_some(),
            self.approved(config),
        ) {
            (true, _, _, _) => "Inspect lesson job outcome",
            (false, true, _, _) => "Inspect model-proposed lesson",
            (false, false, false, _) => "Prepare lesson draft",
            (false, false, true, true) => "Open approved lesson job",
            _ => "Review plan and allowance",
        }
    }

    pub(super) fn result_label(&self) -> &'static str {
        if self.is_workflow_proposal() {
            return "workflow proposal";
        }
        if self.is_lesson() {
            return "lesson";
        }
        if self.is_scope_proposal() {
            return "scope";
        }
        "context"
    }
}

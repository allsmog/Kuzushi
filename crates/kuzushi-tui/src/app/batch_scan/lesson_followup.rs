//! A saved lesson context enters the existing finite Scan planner.
use super::{BatchScanConfig, BatchScanConfigRow};
use crate::app::ShellApp;
use anyhow::{Context, Result};

impl ShellApp {
    pub(crate) fn plan_lesson_context_scan(&mut self) {
        match self.lesson_followup_config() {
            Ok(config) => {
                self.show_study_form(config);
                self.refresh_batch_worker_resolution();
            }
            Err(error) => {
                self.router.lessons.notice = Some(format!("Follow-up needs preparation: {error:#}"))
            }
        }
    }

    fn lesson_followup_config(&self) -> Result<BatchScanConfig> {
        self.ensure_lesson_followup_idle()?;
        let target = self.target_owned().context("Select a repository first")?;
        let reference = self
            .router
            .lessons
            .saved_context
            .as_ref()
            .context("Use u to create a context copy from accepted lessons first")?;
        let input = super::launch::preview_scan_input_for_context(self, reference)?;
        let mut config = BatchScanConfig::load_for_new_study(&target, None);
        self.restore_lesson_followup_accounting(&mut config)?;
        config.study.ensure_accounting_ready()?;
        let source = bind_lesson_accounting(&mut config, reference)?;
        config.study.max_job_attempts = 1;
        config.study.scan_input = Some(input);
        config.cursor = BatchScanConfigRow::ALL
            .iter()
            .position(|row| *row == BatchScanConfigRow::Context)
            .context("The study context row is unavailable; your lesson selection is kept")?;
        config.notice = Some(followup_notice(&source));
        Ok(config)
    }

    fn ensure_lesson_followup_idle(&self) -> Result<()> {
        anyhow::ensure!(
            !self.has_running_work() && self.runtime_state.lesson_write.is_none(),
            "Wait for active work or the context copy to finish; your selection is retained"
        );
        anyhow::ensure!(
            self.router.campaign().batch_scan_config.is_none(),
            "Return to the open study before planning another; its draft is retained"
        );
        Ok(())
    }

    fn restore_lesson_followup_accounting(&self, config: &mut BatchScanConfig) -> Result<()> {
        let Some(generation) = self.router.lessons.generation_study.as_ref() else {
            return Ok(());
        };
        anyhow::ensure!(
            generation.target == config.target,
            "The retained lesson study belongs to another target"
        );
        generation.study.ensure_accounting_ready()?;
        let Some(receipt) = generation
            .context_generation
            .as_ref()
            .and_then(|job| job.receipt.as_ref())
        else {
            return Ok(());
        };
        let allowance = receipt.load_allowance(&config.target)?.context(
            "The lesson investigation accounting is missing; restore it before more work",
        )?;
        config.study.restore_allowance(allowance);
        Ok(())
    }
}

fn followup_notice(source: &kuzushi_core::capabilities::campaign::LessonFollowupContext) -> String {
    let accounting = if source.unaccounted_source_runs > 0 {
        format!(
            " {} source record(s) lack accounting; historical cost is unknown.",
            source.unaccounted_source_runs
        )
    } else {
        " Existing investigation spending and limits are retained.".into()
    };
    format!("Review scope, engines and allowance. Saved context includes {} reviewed lesson(s).{accounting} Model-guided engines read lessons; native scanners use their rules. New jobs need approval. Back returns to Lessons.", source.lesson_count)
}

fn bind_lesson_accounting(
    config: &mut BatchScanConfig,
    reference: &kuzushi_core::ThreatModelRef,
) -> Result<kuzushi_core::capabilities::campaign::LessonFollowupContext> {
    let preferred = config
        .study
        .allowance
        .as_ref()
        .map(|snapshot| snapshot.investigation_id.as_str());
    let source = kuzushi_core::capabilities::campaign::load_lesson_followup_context(
        &config.target,
        reference,
        preferred,
    )?;
    if let Some(allowance) = &source.allowance {
        config.study.restore_allowance(allowance.clone());
    }
    config.prior_run_id = source.source_run_ids.first().cloned();
    config.prior_runs = source
        .source_run_ids
        .iter()
        .map(|run| super::config::BatchPriorRun::pending(run))
        .collect();
    Ok(source)
}

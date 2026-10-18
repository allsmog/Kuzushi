use super::*;
use crate::app::{DisplayedAttempt, ViewHydrationKey};
use kuzushi_core::capabilities::campaign::snapshot::CampaignSnapshot;
use kuzushi_core::run_lifecycle::SafeText;

pub(in crate::ui_view_models::phase_cockpit) fn apply_header(
    body: &super::super::PhaseCockpitBody,
    header: &mut super::super::EngagementHeaderModel,
) {
    let super::super::PhaseCockpitBody::Scan(scan) = body else {
        return;
    };
    if scan.study.is_none()
        || header
            .result_card
            .as_ref()
            .is_some_and(|card| card.has_result_actions())
    {
        return;
    }
    header.next_tools = "c study jobs · jobs inspect run receipts".into();
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ScanStudyModel {
    pub(crate) campaign_id: String,
    pub(crate) target: String,
    pub(crate) queue: Option<ScanStudyQueue>,
    pub(crate) issue: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ScanStudyQueue {
    pub(crate) completed: usize,
    pub(crate) running: usize,
    pub(crate) queued: usize,
    pub(crate) failed: usize,
    pub(crate) deferred: usize,
    pub(crate) unknown: usize,
    pub(crate) jobs: Vec<ScanEngineOutcomeModel>,
}

pub(super) fn scan_study_model(app: &ShellApp) -> Option<ScanStudyModel> {
    let key = app.scan_study_progress_key()?;
    let ViewHydrationKey::ScanStudyProgress { campaign_id } = &key else {
        return None;
    };
    let state = app
        .workbench_cache()
        .borrow()
        .cached_scan_study_progress(app.target()?, &key);
    let (queue, issue) = match state {
        ViewDataState::Ready(Ok(snapshot)) => {
            let queue = queue_model(&snapshot);
            if selected_result_covers_stopped_study(app, &snapshot, &queue) {
                return None;
            }
            (Some(queue), None)
        }
        ViewDataState::Ready(Err(error)) => (None, Some(safe(&error))),
        _ => (None, None),
    };
    Some(ScanStudyModel {
        campaign_id: campaign_id.clone(),
        target: safe(&crate::ui_view_models::scoped_target_path_label(app)),
        queue,
        issue,
    })
}

fn queue_model(snapshot: &CampaignSnapshot) -> ScanStudyQueue {
    let counts = snapshot.state_counts();
    let count = |state| *counts.get(state).unwrap_or(&0);
    let completed = count("completed");
    let running = count("running");
    let queued = count("planned") + count("queued") + count("pending");
    let failed = count("failed");
    let deferred = count("parked");
    ScanStudyQueue {
        completed,
        running,
        queued,
        failed,
        deferred,
        unknown: snapshot
            .jobs
            .len()
            .saturating_sub(completed + running + queued + failed + deferred),
        jobs: snapshot.jobs.iter().map(job_model).collect(),
    }
}

fn job_model(
    job: &kuzushi_core::capabilities::campaign::snapshot::CampaignJobSnapshot,
) -> ScanEngineOutcomeModel {
    ScanEngineOutcomeModel {
        engine: safe(job.display_label.as_deref().unwrap_or(&job.job_id)),
        tool_key: None,
        outcome: safe(match job.state.as_str() {
            "completed" => "complete",
            "planned" | "pending" => "queued",
            state => state,
        }),
        run_ref: job.run_id.clone(),
        detail: job.reason.as_deref().map(safe),
    }
}

fn selected_result_covers_stopped_study(
    app: &ShellApp,
    snapshot: &CampaignSnapshot,
    queue: &ScanStudyQueue,
) -> bool {
    if queue.running + queue.queued + queue.unknown > 0 {
        return false;
    }
    let Some((record, standing)) = app.engagement.displayed_phase_attempt(WorkflowPhase::Scan)
    else {
        return false;
    };
    if standing == DisplayedAttempt::Unresolved {
        return false;
    }
    snapshot
        .jobs
        .iter()
        .filter_map(|job| job.run_id.as_ref())
        .any(|run| record.completed.run_refs.contains(run))
}

fn safe(text: &str) -> String {
    SafeText::condensed_line(text).to_string()
}

#[cfg(test)]
mod tests;

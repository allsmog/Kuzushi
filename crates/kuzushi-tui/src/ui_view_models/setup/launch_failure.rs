use super::*;

pub(super) fn apply_launch_failure(app: &ShellApp, start: &mut SetupReadinessRow) {
    let Some(cause) = app.router.setup().launch_failure() else {
        return;
    };
    if start.blocker.is_none() {
        start.status = "RETRY".into();
        start.tone = SetupReadinessTone::Attention;
    }
    start.detail = format!(
        "LAST START FAILED. {cause}\nNo worker started for this task. The plan is paused and your selections are preserved. Correct the cause, then press Enter on Start Map to retry the selected plan.\nCurrent readiness: {}",
        start.detail
    );
}

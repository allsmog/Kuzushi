use crate::ui_view_models::PhaseSurfaceId;
use crate::ShellApp;

pub(super) fn jobs_binding(app: &ShellApp) -> Option<super::FooterKeybinding> {
    if app.input_mode() != crate::InputMode::Navigate {
        return None;
    }
    let binding = app
        .workbench_view_keybindings_for_plan(None)
        .into_iter()
        .find(|binding| {
            binding.action == crate::app::state_transitions::ViewHotkeyAction::WorkbenchStudyJobs
        })?;
    Some(super::bind(&binding.hint, "study jobs"))
}

pub(super) fn label(app: &ShellApp) -> &'static str {
    let surface = crate::renderer::workbench_scroll_metrics(app).map(|metrics| metrics.surface);
    reader_label(surface, app.scan_study_progress_key().is_some())
}

fn reader_label(surface: Option<PhaseSurfaceId>, study: bool) -> &'static str {
    let engine_label = if study { "jobs" } else { "outcomes" };
    [
        (PhaseSurfaceId::ScanEngines, engine_label),
        (PhaseSurfaceId::ScanReceipt, "receipt"),
        (PhaseSurfaceId::ScanDelta, "summary"),
    ]
    .into_iter()
    .find_map(|(id, label)| (Some(id) == surface).then_some(label))
    .unwrap_or("coverage")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paging_names_the_reader_that_owns_the_keys() {
        for study in [true, false] {
            assert_eq!(
                reader_label(Some(PhaseSurfaceId::ScanReceipt), study),
                "receipt"
            );
            assert_eq!(
                reader_label(Some(PhaseSurfaceId::ScanDelta), study),
                "summary"
            );
            assert_eq!(
                reader_label(Some(PhaseSurfaceId::ScanScope), study),
                "coverage"
            );
            assert_eq!(reader_label(None, study), "coverage");
        }
        assert_eq!(
            reader_label(Some(PhaseSurfaceId::ScanEngines), true),
            "jobs"
        );
        assert_eq!(
            reader_label(Some(PhaseSurfaceId::ScanEngines), false),
            "outcomes"
        );
    }
}

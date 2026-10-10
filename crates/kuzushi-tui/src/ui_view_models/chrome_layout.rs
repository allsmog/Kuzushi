use super::{activity_view_model, ActivityViewModel};
use crate::{ShellApp, ShellView};

/// The Activity view is a focused full-frame dashboard: it carries its own
/// header, in-pane keybind hints, and live feed, so the generic transcript,
/// keybind footer, and status strip would only duplicate it — suppress them.
fn activity_supplies_own_chrome(app: &ShellApp) -> bool {
    matches!(app.shell_view(), ShellView::Activity)
        && matches!(activity_view_model(app), ActivityViewModel::Active(_))
}

fn onboarding_supplies_own_guidance(app: &ShellApp) -> bool {
    matches!(
        app.shell_view(),
        ShellView::TargetPicker | ShellView::PlanningPicker | ShellView::Setup
    )
}

fn compact_answers_supply_guidance(app: &ShellApp, terminal_height: u16) -> bool {
    terminal_height <= 16 && super::answers_own_input(app)
}

pub(crate) fn transcript_chrome_height(app: &ShellApp, terminal_height: u16) -> u16 {
    if compact_reading_hides_transcript(app, terminal_height) {
        return 0;
    }
    // ModuleRun, Quickstart, and Logs hide the embedded transcript strip
    // so they paint full-screen. ModuleRun keeps the prompt; Quickstart
    // (M1 §1.2) needs the room for the guided steps; Logs (M1 §1.1) is the
    // transcript so a strip would be redundant. Activity hides all generic
    // chrome via `activity_supplies_own_chrome`.
    if activity_supplies_own_chrome(app)
        || onboarding_supplies_own_guidance(app)
        || hides_transcript_chrome(&app.shell_view())
        || terminal_height < 12
    {
        return 0;
    }
    if terminal_height == 12 {
        return 1;
    }
    2
}

fn compact_reading_hides_transcript(app: &ShellApp, height: u16) -> bool {
    compact_answers_supply_guidance(app, height)
        || (app.shell_view() == ShellView::Scene && height < 20)
}

pub(crate) fn compact_gallery_notice(app: &ShellApp, height: u16) -> bool {
    app.shell_view() == ShellView::Scene && height <= 12
}

pub(crate) fn keybind_footer_chrome_height(
    app: &ShellApp,
    terminal_height: u16,
    terminal_width: u16,
) -> u16 {
    if compact_answers_supply_guidance(app, terminal_height) {
        return 0;
    }
    if activity_supplies_own_chrome(app)
        || onboarding_supplies_own_guidance(app)
        || terminal_height < 8
    {
        return 0;
    }
    if terminal_width < 70 && terminal_height >= 9 {
        return 3;
    }
    2
}

pub(crate) fn status_footer_chrome_height(app: &ShellApp, terminal_height: u16) -> u16 {
    if activity_supplies_own_chrome(app) || terminal_height < 6 {
        return 0;
    }
    1
}

/// The context rail auto-appears only above this width. 120 is already spoken
/// for — it unlocks the Workbench Dense composition and the Fix reference
/// layout — so the rail must not steal columns there and silently demote them.
pub(crate) const RAIL_AUTO_MIN_WIDTH: u16 = 140;
/// An explicit `rail` toggle may force the rail down to this width; below it
/// the body would drop under the 78/50 multi-region breakpoints.
pub(crate) const RAIL_FORCE_MIN_WIDTH: u16 = 100;
/// Total rail columns, including its 2-column separator gutter.
pub(crate) const RAIL_WIDTH: u16 = 36;

/// Columns the context rail occupies at `terminal_width` — 0 when hidden.
///
/// Three-state visibility: the persisted `ui.rail` policy (`Hidden` wins
/// everywhere), the ephemeral force-open (an explicit `rail` this session,
/// honored down to `RAIL_FORCE_MIN_WIDTH`), then the automatic width test.
/// Onboarding views own their whole frame and stay rail-free.
pub(crate) fn rail_width(app: &ShellApp, terminal_width: u16) -> u16 {
    if super::answers_visible(app) {
        return 0;
    }
    if !app.ui().rail_enabled() || onboarding_supplies_own_guidance(app) {
        return 0;
    }
    let wide_enough = terminal_width >= RAIL_AUTO_MIN_WIDTH
        || (app.ui().rail_force_open() && terminal_width >= RAIL_FORCE_MIN_WIDTH);
    if wide_enough {
        RAIL_WIDTH
    } else {
        0
    }
}

fn hides_transcript_chrome(view: &ShellView) -> bool {
    matches!(
        view,
        ShellView::ModuleRun
            | ShellView::Quickstart
            | ShellView::Logs
            | ShellView::Workbench
            | ShellView::Report
            | ShellView::Keymap
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;

    fn app_in_view(view: ShellView) -> ShellApp {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(view);
        app
    }

    #[test]
    fn transcript_chrome_height_hides_during_module_run() {
        assert_eq!(
            transcript_chrome_height(&app_in_view(ShellView::ModuleRun), 24),
            0
        );
    }

    #[test]
    fn transcript_chrome_height_hides_for_quickstart_and_logs() {
        // M1 §1.1 / §1.2: full-screen views suppress the embedded transcript.
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(ShellView::Quickstart);
        assert_eq!(transcript_chrome_height(&app, 24), 0);

        app.set_shell_view(ShellView::Logs);
        assert_eq!(transcript_chrome_height(&app, 24), 0);
    }

    #[test]
    fn transcript_chrome_height_hides_for_workbench() {
        assert_eq!(
            transcript_chrome_height(&app_in_view(ShellView::Workbench), 24),
            0
        );
    }

    #[test]
    fn report_keeps_reading_space_instead_of_repeating_command_history() {
        let app = app_in_view(ShellView::Report);
        for height in [12, 20, 24, 36, 48, 89] {
            assert_eq!(transcript_chrome_height(&app, height), 0);
        }
    }

    #[test]
    fn transcript_chrome_height_requires_room() {
        let app = ShellApp::new(V2Config::default(), None);

        assert_eq!(transcript_chrome_height(&app, 11), 0);
        assert_eq!(transcript_chrome_height(&app, 12), 1);
        assert_eq!(transcript_chrome_height(&app, 13), 2);
    }

    #[test]
    fn activity_view_suppresses_all_generic_chrome() {
        let mut app = app_in_view(ShellView::Activity);
        app.set_activity(Some(crate::ActivitySession::new("run-active")));

        assert_eq!(transcript_chrome_height(&app, 24), 0);
        assert_eq!(keybind_footer_chrome_height(&app, 24, 80), 0);
        assert_eq!(status_footer_chrome_height(&app, 24), 0);
    }

    #[test]
    fn idle_activity_uses_standard_orientation_chrome() {
        let app = app_in_view(ShellView::Activity);

        assert_eq!(transcript_chrome_height(&app, 24), 2);
        assert_eq!(keybind_footer_chrome_height(&app, 24, 80), 2);
        assert_eq!(status_footer_chrome_height(&app, 24), 1);
    }

    #[test]
    fn onboarding_gates_keep_only_local_guidance_and_status() {
        let app = app_in_view(ShellView::TargetPicker);

        assert_eq!(transcript_chrome_height(&app, 24), 0);
        assert_eq!(keybind_footer_chrome_height(&app, 24, 60), 0);
        assert_eq!(status_footer_chrome_height(&app, 24), 1);
    }

    #[test]
    fn keybind_footer_chrome_height_requires_room() {
        let app = ShellApp::new(V2Config::default(), None);

        assert_eq!(keybind_footer_chrome_height(&app, 7, 80), 0);
        assert_eq!(keybind_footer_chrome_height(&app, 8, 80), 2);
    }

    #[test]
    fn keybind_footer_wraps_below_70_cols_when_there_is_room() {
        let app = ShellApp::new(V2Config::default(), None);

        assert_eq!(keybind_footer_chrome_height(&app, 24, 69), 3);
        assert_eq!(keybind_footer_chrome_height(&app, 24, 70), 2);
    }

    #[test]
    fn status_footer_chrome_height_requires_room() {
        let app = ShellApp::new(V2Config::default(), None);

        assert_eq!(status_footer_chrome_height(&app, 5), 0);
        assert_eq!(status_footer_chrome_height(&app, 6), 1);
    }

    #[test]
    fn rail_auto_appears_only_at_140_columns() {
        let app = ShellApp::new(V2Config::default(), None);

        assert_eq!(rail_width(&app, 139), 0);
        assert_eq!(rail_width(&app, 140), RAIL_WIDTH);
    }

    #[test]
    fn rail_never_steals_the_workbench_dense_breakpoint() {
        // 120 unlocks Dense/Fix-reference layouts; the rail must leave it alone.
        let app = ShellApp::new(V2Config::default(), None);

        assert_eq!(rail_width(&app, 120), 0);
    }

    #[test]
    fn rail_hidden_policy_wins_at_any_width() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.ui_mut().set_rail_enabled(false);

        assert_eq!(rail_width(&app, 200), 0);
    }

    #[test]
    fn rail_force_open_reaches_down_to_100_columns() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.ui_mut().set_rail_force_open(true);

        assert_eq!(rail_width(&app, 99), 0);
        assert_eq!(rail_width(&app, 100), RAIL_WIDTH);
    }

    #[test]
    fn onboarding_views_stay_rail_free() {
        let app = app_in_view(ShellView::TargetPicker);

        assert_eq!(rail_width(&app, 200), 0);
    }
}

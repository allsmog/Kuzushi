use crate::{ShellApp, ShellView};

/// The Activity view is a focused full-frame dashboard: it carries its own
/// header, in-pane keybind hints, and live feed, so the generic transcript,
/// keybind footer, and status strip would only duplicate it — suppress them.
fn activity_supplies_own_chrome(app: &ShellApp) -> bool {
    matches!(app.shell_view, ShellView::Activity)
}

pub(crate) fn transcript_chrome_height(app: &ShellApp, terminal_height: u16) -> u16 {
    let suppressed = activity_supplies_own_chrome(app)
        || matches!(app.shell_view, ShellView::ModuleRun)
        || terminal_height < 12;
    if suppressed {
        return 0;
    }
    2
}

pub(crate) fn keybind_footer_chrome_height(app: &ShellApp, terminal_height: u16) -> u16 {
    if activity_supplies_own_chrome(app) || terminal_height < 8 {
        return 0;
    }
    2
}

pub(crate) fn status_footer_chrome_height(app: &ShellApp, terminal_height: u16) -> u16 {
    if activity_supplies_own_chrome(app) || terminal_height < 6 {
        return 0;
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;

    fn app_in_view(view: ShellView) -> ShellApp {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = view;
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
    fn transcript_chrome_height_requires_room() {
        let app = ShellApp::new(V2Config::default(), None);

        assert_eq!(transcript_chrome_height(&app, 11), 0);
        assert_eq!(transcript_chrome_height(&app, 12), 2);
    }

    #[test]
    fn activity_view_suppresses_all_generic_chrome() {
        let app = app_in_view(ShellView::Activity);

        assert_eq!(transcript_chrome_height(&app, 24), 0);
        assert_eq!(keybind_footer_chrome_height(&app, 24), 0);
        assert_eq!(status_footer_chrome_height(&app, 24), 0);
    }

    #[test]
    fn keybind_footer_chrome_height_requires_room() {
        let app = ShellApp::new(V2Config::default(), None);

        assert_eq!(keybind_footer_chrome_height(&app, 7), 0);
        assert_eq!(keybind_footer_chrome_height(&app, 8), 2);
    }

    #[test]
    fn status_footer_chrome_height_requires_room() {
        let app = ShellApp::new(V2Config::default(), None);

        assert_eq!(status_footer_chrome_height(&app, 5), 0);
        assert_eq!(status_footer_chrome_height(&app, 6), 1);
    }
}

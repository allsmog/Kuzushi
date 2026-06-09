use crate::{ShellApp, ShellView};

/// The Activity view is a focused full-frame dashboard: it renders its own
/// keybind hints and header status in-pane and its feed pane is the live
/// output, so the generic transcript/footer/status chrome is suppressed there.
fn chrome_hidden_for_view(app: &ShellApp) -> bool {
    matches!(app.shell_view, ShellView::Activity)
}

pub(crate) fn transcript_chrome_height(app: &ShellApp, terminal_height: u16) -> u16 {
    if chrome_hidden_for_view(app)
        || matches!(app.shell_view, ShellView::ModuleRun)
        || terminal_height < 12
    {
        return 0;
    }
    2
}

pub(crate) fn keybind_footer_chrome_height(app: &ShellApp, terminal_height: u16) -> u16 {
    if !chrome_hidden_for_view(app) && terminal_height >= 8 {
        2
    } else {
        0
    }
}

pub(crate) fn status_footer_chrome_height(app: &ShellApp, terminal_height: u16) -> u16 {
    if !chrome_hidden_for_view(app) && terminal_height >= 6 {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn transcript_chrome_height_hides_during_module_run() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::ModuleRun;

        assert_eq!(transcript_chrome_height(&app, 24), 0);
    }

    #[test]
    fn transcript_chrome_height_requires_room() {
        let app = ShellApp::new(V2Config::default(), None);

        assert_eq!(transcript_chrome_height(&app, 11), 0);
        assert_eq!(transcript_chrome_height(&app, 12), 2);
    }
}

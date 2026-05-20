use crate::{ShellApp, ShellView};

pub(crate) fn transcript_chrome_height(app: &ShellApp, terminal_height: u16) -> u16 {
    // ModuleRun, Quickstart, and Logs hide the embedded transcript strip
    // so they paint full-screen. ModuleRun keeps the prompt; Quickstart
    // (M1 §1.2) needs the room for the guided steps; Logs (M1 §1.1) is the
    // transcript so a strip would be redundant.
    if hides_transcript_chrome(&app.shell_view) || terminal_height < 12 {
        return 0;
    }
    2
}

fn hides_transcript_chrome(view: &ShellView) -> bool {
    matches!(
        view,
        ShellView::ModuleRun | ShellView::Quickstart | ShellView::Logs
    )
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
    fn transcript_chrome_height_hides_for_quickstart_and_logs() {
        // M1 §1.1 / §1.2: full-screen views suppress the embedded transcript.
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Quickstart;
        assert_eq!(transcript_chrome_height(&app, 24), 0);

        app.shell_view = ShellView::Logs;
        assert_eq!(transcript_chrome_height(&app, 24), 0);
    }

    #[test]
    fn transcript_chrome_height_requires_room() {
        let app = ShellApp::new(V2Config::default(), None);

        assert_eq!(transcript_chrome_height(&app, 11), 0);
        assert_eq!(transcript_chrome_height(&app, 12), 2);
    }
}

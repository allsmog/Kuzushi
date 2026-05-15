use crate::{ShellApp, ShellView};

pub(crate) fn transcript_chrome_height(app: &ShellApp, terminal_height: u16) -> u16 {
    if matches!(app.shell_view, ShellView::ModuleRun) || terminal_height < 12 {
        return 0;
    }
    2
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

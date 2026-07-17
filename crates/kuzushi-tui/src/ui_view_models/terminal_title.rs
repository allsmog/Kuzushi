use super::{active_workbench_page, view_status_segment, ShellApp};
use crate::{AttentionBroker, ShellView};

pub(crate) fn terminal_title(app: &ShellApp) -> String {
    let attention = AttentionBroker::from_app(app);
    if let Some(primary) = attention.primary() {
        return format!("Kuzushi · [!] {}", primary.kind.title());
    }
    match app.shell_view() {
        ShellView::Workbench => format!("Kuzushi · {}", active_workbench_page(app).title()),
        ShellView::Activity => app
            .activity()
            .and_then(|session| session.origin_phase)
            .map_or_else(
                || "Kuzushi · RUN FOCUS".to_string(),
                |phase| format!("Kuzushi · RUN FOCUS · {}", phase.label()),
            ),
        _ => format!("Kuzushi · {}", view_status_segment(app)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::SetupEditor;
    use kuzushi_core::V2Config;

    #[test]
    fn attention_replaces_location_without_exposing_credential_details() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.router
            .setup_mut()
            .begin_editor(SetupEditor::Credentials);

        let title = terminal_title(&app);

        assert_eq!(title, "Kuzushi · [!] CREDENTIALS REQUIRED");
        assert!(!title.contains("API"));
    }
}

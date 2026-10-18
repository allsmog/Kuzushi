use super::keybindings::FooterKeybinding;
use super::ShellApp;
use crate::state_transitions::ViewHotkeyAction;

/// Project the same return binding searched by the active view dispatcher.
pub(crate) fn linked_study_return_binding(app: &ShellApp) -> Option<FooterKeybinding> {
    if !app.study_navigation_return_active()
        || app.input_mode() != crate::InputMode::Navigate
        || app.notice_captures_escape()
    {
        return None;
    }
    app.view_keybindings()
        .into_iter()
        .find(|binding| binding.action == ViewHotkeyAction::CampaignBackToList)
        .map(|binding| FooterKeybinding {
            key: binding.hint,
            label: binding.label,
        })
}

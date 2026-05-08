use super::view_keybinding_groups::{
    actor_detail_keybindings, findings_keybindings, prompts_editor_keybindings, threat_keybindings,
    tune_keybindings,
};
use super::view_keybinding_helpers::{bind, pause_scan_keybindings, resume_scan_keybindings};
use super::*;

impl ShellApp {
    pub(crate) fn view_keybindings(&self) -> Vec<ViewKeybinding> {
        match self.shell_view {
            ShellView::Findings if !self.findings.is_empty() => findings_keybindings(),
            ShellView::Threat(_) => threat_keybindings(),
            ShellView::ModuleRun => self.module_run_keybindings(),
            ShellView::ActorDetail(_) => actor_detail_keybindings(),
            ShellView::PromptsEditor => prompts_editor_keybindings(),
            ShellView::Tune => tune_keybindings(),
            _ => Vec::new(),
        }
    }

    pub(super) fn module_run_keybindings(&self) -> Vec<ViewKeybinding> {
        let mut bindings = (1..=4)
            .map(|index| {
                bind(
                    HotkeyTrigger::Char(char::from_digit(index as u32, 10).unwrap()),
                    "1..4",
                    "actor",
                    ViewHotkeyAction::ActorDetail(index),
                )
            })
            .collect::<Vec<_>>();
        if self.can_pause_scan_hotkey() {
            bindings.extend(pause_scan_keybindings());
        }
        if self.can_resume_scan_hotkey() {
            bindings.extend(resume_scan_keybindings());
        }
        bindings
    }

    pub(super) fn can_pause_scan_hotkey(&self) -> bool {
        self.scan.as_ref().is_some_and(|scan| scan.running)
            && self.scan_cancel.is_some()
            && !self.is_scan_paused()
    }

    pub(super) fn can_resume_scan_hotkey(&self) -> bool {
        self.scan.as_ref().is_some_and(|scan| scan.running)
            && self.scan_cancel.is_some()
            && self.is_scan_paused()
    }
}

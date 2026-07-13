use super::{bind, push_view_keybindings, FooterKeybinding};
use crate::app::{WorkbenchPage, WorkbenchPane};
use crate::ui_view_models::active_workbench_page;
use crate::ui_view_models::WORKBENCH_REPORT_COMMAND;
use crate::{ShellApp, ShellView};

pub(super) fn keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    matches!(app.shell_view(), ShellView::Workbench).then(|| workbench_keybindings(app))
}

fn workbench_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    // Keep the phase-native controls copyable at ordinary terminal widths.
    // This is presentation order only; the input dispatcher retains its own
    // first-match ordering.
    let mut bindings = Vec::new();
    push_view_keybindings(&mut bindings, app);
    match focused_enter_binding(app) {
        Some(binding) => replace_enter_binding(&mut bindings, binding),
        None => bindings.retain(|binding| binding.key != "Enter"),
    }
    prioritize_phase_controls(&mut bindings, app);
    bindings.extend([
        bind("Ctrl+G", "palette"),
        bind("scan", "guided plan"),
        bind("run sast:scan {}", "rescan now"),
    ]);
    if !app.findings().is_empty() {
        bindings.push(bind(WORKBENCH_REPORT_COMMAND, "export report"));
    }
    bindings.push(bind("Ctrl+C", "exit"));
    bindings
}

fn prioritize_phase_controls(bindings: &mut [FooterKeybinding], app: &ShellApp) {
    // Preserve the PDF phase controls before secondary cursor shortcuts at
    // compact widths. This changes presentation order only.
    const PHASE_KEYS: [&str; 5] = ["1..4", "Tab", "Z", "z", "Enter"];
    const REVIEW_KEYS: [&str; 12] = [
        "q",
        "Enter",
        "j/k/↑/↓",
        "v",
        "x",
        "c",
        "n/N",
        "Tab",
        "1..4",
        "Z",
        "z",
        "g/G",
    ];
    let keys = if app.router.workbench().focus() == WorkbenchPane::Findings {
        REVIEW_KEYS.as_slice()
    } else {
        PHASE_KEYS.as_slice()
    };
    bindings.sort_by_key(|binding| {
        keys.iter()
            .position(|key| *key == binding.key)
            .unwrap_or(keys.len())
    });
}

fn replace_enter_binding(bindings: &mut [FooterKeybinding], replacement: FooterKeybinding) {
    if let Some(binding) = bindings.iter_mut().find(|binding| binding.key == "Enter") {
        *binding = replacement;
    }
}

fn focused_enter_binding(app: &ShellApp) -> Option<FooterKeybinding> {
    let page = active_workbench_page(app);
    let focus = app.router.workbench().focus();
    let viewport = app.viewport();
    (focus == WorkbenchPane::Findings
        && page
            .interactive_panes_for_viewport(
                app.router.workbench().center_mode(),
                viewport.columns,
                viewport.rows,
            )
            .contains(&focus))
    .then(|| {
        if page == WorkbenchPage::Coverage {
            bind("Enter", "review")
        } else {
            bind("Enter", "open")
        }
    })
}

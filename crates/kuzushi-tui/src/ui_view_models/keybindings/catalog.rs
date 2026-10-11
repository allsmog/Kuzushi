use super::{bind, FooterKeybinding};
use crate::{ShellApp, ShellView};

pub(super) fn owned_picker_keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    if !app.catalog_picker_owns_input() {
        return None;
    }
    let mut bindings = super::active::active_keybindings(app)
        .unwrap_or_else(|| vec![super::interrupt_binding(app)]);
    let activation = catalog_activation_label(app);
    bindings.insert(1, bind("Enter", activation));
    bindings.insert(2, bind("↑/↓", "action"));
    bindings.insert(3, bind("PgUp/PgDn", "page"));
    super::push_view_keybindings(&mut bindings, app);
    bindings.retain(|binding| binding.key != "Enter" || binding.label == activation);
    bindings.push(bind("Tab", "complete"));
    bindings.push(bind("type", "command"));
    bindings.push(bind("Ctrl+G", "palette"));
    if app.router.overlay_origin().is_none() {
        bindings.retain(|binding| binding.key != "Esc");
        bindings.push(root_catalog_escape_binding(app));
    }
    Some(bindings)
}

fn catalog_activation_label(app: &ShellApp) -> &'static str {
    if app.target().is_some() {
        "load"
    } else {
        "target picker"
    }
}

fn root_catalog_escape_binding(app: &ShellApp) -> FooterKeybinding {
    match app.input_mode() {
        crate::InputMode::Prompt => bind("Esc", "nav mode"),
        crate::InputMode::Navigate => bind("Esc", "prompt"),
    }
}

pub(super) fn keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    match app.shell_view() {
        ShellView::Home => Some(home_keybindings()),
        ShellView::Catalog if !app.router.catalog().is_expanded() => {
            Some(collapsed_catalog_keybindings())
        }
        ShellView::Catalog => Some(expanded_catalog_keybindings()),
        ShellView::Recommend => Some(recommend_keybindings(app)),
        _ => None,
    }
}

fn home_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("Ctrl+G", "palette"),
        bind("n", "next phase"),
        bind("modules", "browse"),
        bind("options sast:scan", "tune scan"),
        bind("scan", "Scan phase planner"),
        bind("Ctrl+C", "exit"),
    ]
}

fn collapsed_catalog_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("Ctrl+G", "palette"),
        bind("j/k", "action"),
        bind("Enter", "load"),
        bind("e", "expert"),
        bind("tools", "inventory"),
        bind("Esc", "back"),
    ]
}

fn expanded_catalog_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("Ctrl+G", "palette"),
        bind("j/k", "action"),
        bind("PgUp/PgDn", "scroll"),
        bind("Enter", "load"),
        bind("e", "phase only"),
        bind("tools", "full inventory"),
        bind("?", "help"),
    ]
}

fn recommend_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let mut bindings = vec![bind("Ctrl+G", "palette")];
    super::push_view_keybindings(&mut bindings, app);
    bindings
}

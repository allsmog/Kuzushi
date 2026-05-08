use super::*;

pub(in crate::renderer::chrome::footer::keybindings) fn default_keybindings(
) -> Vec<(&'static str, &'static str)> {
    vec![
        ("Enter", "run command"),
        ("back", "home"),
        ("help", "help"),
        ("Ctrl+C", "exit"),
    ]
}

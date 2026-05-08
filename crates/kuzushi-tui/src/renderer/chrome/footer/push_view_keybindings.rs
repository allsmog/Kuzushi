use super::*;

pub(crate) fn push_view_keybindings(
    bindings: &mut Vec<(&'static str, &'static str)>,
    app: &ShellApp,
) {
    for binding in app.view_keybindings() {
        if !bindings
            .iter()
            .any(|(hint, label)| *hint == binding.hint && *label == binding.label)
        {
            bindings.push((binding.hint, binding.label));
        }
    }
}

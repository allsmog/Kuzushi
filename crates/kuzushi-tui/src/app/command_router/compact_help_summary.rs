use super::*;

pub(crate) fn compact_help_summary() -> String {
    let commands = shell_command_specs()
        .map(|spec| {
            if spec.command.starts_with('?') {
                spec.command.to_string()
            } else {
                format!("/{}", spec.command)
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    let examples = shell_help_examples();
    if examples.is_empty() {
        commands
    } else {
        format!("Examples: {}. Commands: {commands}", examples.join(", "))
    }
}

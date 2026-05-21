use super::*;

pub(crate) fn compact_help_summary() -> String {
    let examples = shell_help_examples();
    if examples.is_empty() {
        "type `help` for the full command reference".to_string()
    } else {
        format!(
            "Examples: {}. Next: `help` for the full command reference",
            examples.join(", ")
        )
    }
}

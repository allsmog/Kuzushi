use crate::{ShellApp, ShellView};

type Bindings = Vec<(String, String)>;

pub(super) fn applies(app: &ShellApp, bindings: &[(String, String)]) -> bool {
    app.shell_view() == ShellView::Replay
        && bindings.iter().any(|(key, label)| {
            key == "Tab"
                && matches!(
                    label.as_str(),
                    "full receipt" | "result" | "summary" | "inputs"
                )
        })
}

pub(super) fn rows(bindings: Bindings) -> (Bindings, Bindings) {
    let separate_escape = escape_needs_separate_row(&bindings);
    let (mut primary, mut secondary): (Bindings, Bindings) = bindings
        .into_iter()
        .map(compact_binding)
        .partition(|(key, _)| primary_binding(key, separate_escape));
    primary.sort_by_key(|(key, _)| primary_priority(key));
    secondary.sort_by_key(|(key, _)| secondary_priority(key));
    (primary, secondary)
}

fn escape_needs_separate_row(bindings: &[(String, String)]) -> bool {
    bindings.iter().any(|(key, label)| match key.as_str() {
        "Ctrl+C" => label != "exit",
        "Esc" => label != "back",
        _ => false,
    })
}

fn primary_binding(key: &str, separate_escape: bool) -> bool {
    match key {
        "Tab" | "Ctrl+C" => true,
        "Esc" => !separate_escape,
        _ => false,
    }
}

fn primary_priority(key: &str) -> u8 {
    match key {
        "Ctrl+C" => 0,
        "Tab" => 1,
        _ => 2,
    }
}

fn secondary_priority(key: &str) -> u8 {
    match key {
        "Esc" => 0,
        "PgUp/Dn" => 1,
        _ => 2,
    }
}

fn compact_binding((key, label): (String, String)) -> (String, String) {
    let compact = match (key.as_str(), label.as_str()) {
        ("Tab", "full receipt") => ("Tab", "receipt"),
        ("Esc", "dismiss notice") => ("Esc", "dismiss"),
        ("PgUp/PgDn", "scroll") => ("PgUp/Dn", "read"),
        _ => return (key, label),
    };
    (compact.0.into(), compact.1.into())
}

#[cfg(test)]
mod tests;

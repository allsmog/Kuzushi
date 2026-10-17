type Bindings = Vec<(String, String)>;

pub(super) fn has_findings_link(bindings: &[(String, String)]) -> bool {
    bindings
        .iter()
        .any(|(key, label)| key == "f" && label == "findings at paths")
}

pub(super) fn rows(bindings: Bindings) -> (Bindings, Bindings) {
    const PRIMARY: [&str; 3] = ["j/k/↑/↓", "f", "Enter"];
    let (primary, mut secondary): (Bindings, Bindings) = bindings
        .into_iter()
        .partition(|(key, _)| PRIMARY.contains(&key.as_str()));
    let primary = primary.into_iter().map(compact_binding).collect();
    secondary.sort_by_key(|(key, _)| secondary_priority(key));
    let secondary = secondary.into_iter().map(compact_binding).collect();
    (primary, secondary)
}

fn secondary_priority(key: &str) -> u8 {
    match key {
        "Ctrl+C" | "Esc/q" | "Esc" | "q" => 0,
        "PgUp/PgDn" => 1,
        "Tab" => 2,
        _ => 3,
    }
}

fn compact_binding((key, label): (String, String)) -> (String, String) {
    let compact = match (key.as_str(), label.as_str()) {
        ("j/k/↑/↓", "select") => ("j/k", "select"),
        ("j/k/↑/↓", "context") => ("j/k", "items"),
        ("f", "findings at paths") => ("f", "findings"),
        ("Enter", "context") => ("Enter", "links"),
        ("Enter", "topology") => ("Enter", "graph"),
        ("Esc/q", "leave") => ("Esc/q", "back"),
        ("q", "leave") => ("q", "back"),
        ("PgUp/PgDn", "detail") => ("PgUp/Dn", "read"),
        _ => return (key, label),
    };
    (compact.0.into(), compact.1.into())
}

#[cfg(test)]
mod tests {
    use super::super::{keybindings_line_for_wrapped_row, OverflowHint};
    use super::*;

    #[test]
    fn compact_dfd_keeps_selection_findings_inspection_and_exit_visible() {
        for width in [40, 60] {
            for focused in [false, true] {
                let bindings = bindings(focused);
                assert!(has_findings_link(&bindings));
                let (top, bottom) = rows(bindings);
                let (top, overflow) =
                    keybindings_line_for_wrapped_row(top, width, OverflowHint::Defer);
                let (bottom, _) =
                    keybindings_line_for_wrapped_row(bottom, width, OverflowHint::ShowIf(overflow));
                let text = [top, bottom]
                    .into_iter()
                    .flat_map(|line| line.spans)
                    .map(|span| span.content.to_string())
                    .collect::<String>();
                for required in ["j/k", "f findings", "Enter", "back"] {
                    assert!(text.contains(required), "{width} focused={focused}: {text}");
                }
            }
        }
    }

    #[test]
    fn active_cancellation_keeps_its_footer_control() {
        let mut bindings = bindings(false);
        bindings.insert(0, ("Ctrl+C".into(), "cancel".into()));
        let (_, bottom) = rows(bindings);
        let (line, _) = keybindings_line_for_wrapped_row(bottom, 40, OverflowHint::ShowIf(true));
        let text = line
            .spans
            .into_iter()
            .map(|span| span.content.to_string())
            .collect::<String>();
        assert!(text.contains("Ctrl+C cancel"), "{text}");
        assert!(text.contains("Esc/q back"), "{text}");
    }

    fn bindings(focused: bool) -> Bindings {
        let mut bindings = vec![
            ("j/k/↑/↓", if focused { "context" } else { "select" }),
            ("f", "findings at paths"),
            ("g", "regenerate scope"),
            ("Enter", if focused { "topology" } else { "context" }),
            ("PgUp/PgDn", "detail"),
            ("Tab", "next page"),
            ("Shift+Tab", "prev page"),
        ];
        if focused {
            bindings.extend([("Esc", "collapse"), ("q", "leave")]);
        } else {
            bindings.push(("Esc/q", "leave"));
        }
        bindings
            .into_iter()
            .map(|(key, label)| (key.into(), label.into()))
            .collect()
    }
}

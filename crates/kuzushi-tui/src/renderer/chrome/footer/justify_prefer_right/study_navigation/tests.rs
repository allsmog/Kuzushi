use super::super::{keybindings_line_for_wrapped_row, OverflowHint};
use super::*;

fn bindings(jobs: &str, interrupt: &str) -> Bindings {
    [
        ("Ctrl+T", "answers"),
        ("Esc", "prompt"),
        ("PgUp/PgDn", "jobs"),
        (jobs, "study jobs"),
        ("n", "Use & Review"),
        ("u", "Use scan"),
        ("o", "Open"),
        ("r", "Run again"),
        ("Ctrl+C", interrupt),
    ]
    .into_iter()
    .map(|(key, label)| (key.into(), label.into()))
    .collect()
}

#[test]
fn compact_study_controls_keep_reading_jobs_and_exit_visible() {
    for width in [40, 60] {
        for jobs in ["c", "C"] {
            for interrupt in ["exit", "request abort", "wait cleanup"] {
                let (top, bottom) = rows(bindings(jobs, interrupt));
                let (top, overflow) =
                    keybindings_line_for_wrapped_row(top, width, OverflowHint::Defer);
                let (bottom, _) =
                    keybindings_line_for_wrapped_row(bottom, width, OverflowHint::ShowIf(overflow));
                let text = format!("{top}\n{bottom}");
                for required in [
                    "Esc prompt",
                    "Ctrl+C",
                    interrupt,
                    "PgUp/Dn read",
                    &format!("{jobs} jobs"),
                ] {
                    assert!(text.contains(required), "{width}: {text}");
                }
                assert!(top.width() <= width && bottom.width() <= width);
                assert!(text.matches("/keys all").count() <= 1, "{text}");
            }
        }
    }
}

#[test]
fn single_row_study_keeps_essential_controls_and_other_views_keep_their_order() {
    let (line, _) = keybindings_line_for_wrapped_row(
        single_row(bindings("C", "exit")),
        80,
        OverflowHint::ShowIf(false),
    );
    let text = line.to_string();
    for required in ["Esc prompt", "Ctrl+C exit", "PgUp/Dn read", "C jobs"] {
        assert!(text.contains(required), "{text}");
    }
    let ordinary = vec![("Tab".into(), "complete".into())];
    assert!(!applies(&ordinary));
    assert_eq!(single_row(ordinary.clone()), ordinary);
}

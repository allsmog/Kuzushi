use super::super::{keybindings_line_for_wrapped_row, OverflowHint};
use super::*;

#[test]
fn compact_receipt_controls_keep_switch_escape_paging_and_interrupt_visible() {
    for width in [40, 60] {
        for interrupt in ["exit", "request abort", "wait cleanup"] {
            for escape in ["back", "dismiss notice"] {
                for tab in ["full receipt", "result", "summary", "inputs"] {
                    let (top, bottom) = rows(bindings(interrupt, escape, tab));
                    let (top, overflow) =
                        keybindings_line_for_wrapped_row(top, width, OverflowHint::Defer);
                    let (bottom, _) = keybindings_line_for_wrapped_row(
                        bottom,
                        width,
                        OverflowHint::ShowIf(overflow),
                    );
                    assert!(top.width() <= width && bottom.width() <= width);
                    let text = format!("{top}\n{bottom}");
                    for required in ["Tab ", "Esc ", "PgUp/Dn read", "Ctrl+C "] {
                        assert!(
                            text.contains(required),
                            "{width} {interrupt} {escape} {tab}: {text}"
                        );
                    }
                    assert!(text.contains(interrupt), "{text}");
                    assert!(text.matches("/keys all").count() <= 1, "{text}");
                    if width == 40 {
                        assert!(text.contains("/keys all"), "{text}");
                    }
                }
            }
        }
    }
}

#[test]
fn composer_completion_does_not_receive_receipt_layout() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_shell_view(ShellView::Replay);
    assert!(!applies(&app, &bindings("exit", "back", "complete")));
    assert!(applies(&app, &bindings("exit", "back", "full receipt")));
    app.set_shell_view(ShellView::Trace);
    assert!(!applies(&app, &bindings("exit", "back", "full receipt")));
}

fn bindings(interrupt: &str, escape: &str, tab: &str) -> Bindings {
    [
        ("Esc", escape),
        ("Tab", tab),
        ("PgUp/PgDn", "scroll"),
        ("Home/End", "start/end"),
        ("Ctrl+C", interrupt),
        ("Ctrl+T", "answers"),
    ]
    .into_iter()
    .map(|(key, label)| (key.into(), label.into()))
    .collect()
}

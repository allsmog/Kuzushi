use super::*;

pub(super) fn append_empty_catalog(area: Rect, lines: &mut Vec<Line<'static>>) {
    lines.push(divider("MODULES · empty", area.width));
    lines.extend(empty_state_panel(
        "no modules loaded",
        &[
            "the native module registry is empty.",
            "this almost always means a plugin failed to register.",
        ],
        &[
            ("doctor", "preflight checks for missing tools / plugins"),
            ("modules", "re-inspect the native registry"),
        ],
    ));
}

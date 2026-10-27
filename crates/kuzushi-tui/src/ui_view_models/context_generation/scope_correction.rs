use super::*;

pub(crate) const CORRECTION_CONTROLS: &str =
    "Enter newline · Ctrl+S save\nCtrl+R reset · Esc kept · PgUp/Dn";

pub(crate) fn correction_notice(state: &crate::app::ScopeCorrectionEditor) -> &str {
    state.notice.as_deref().unwrap_or("Local edit. Validates original source and preserves exclusions/shared discovery. Saves an unaccepted revision; no model request.")
}

pub(super) fn lines(state: &crate::app::ScopeCorrectionEditor, width: usize) -> Vec<String> {
    let mut lines = vec!["CORRECT SCOPE JSON".into(), correction_notice(state).into()];
    lines.extend(
        state
            .editor
            .text()
            .lines()
            .map(super::diagnosis::escape_controls),
    );
    lines.extend(CORRECTION_CONTROLS.lines().map(str::to_owned));
    lines
        .into_iter()
        .flat_map(|line| wrap_text(&line, width.max(1)))
        .collect()
}

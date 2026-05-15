pub(in crate::renderer) use super::*;

pub(in crate::renderer) use justify_prefer_right::*;
pub(in crate::renderer) use render_status_footer::*;
mod justify_prefer_right;
/// Render the bottom keybind row to match `design/mockups/_shared.jsx::footer`:
///   `<key>` in accent, `<hint>` in muted, three-space separator between
///   pairs.  Keys flow left-to-right and the row is truncated, with an
///   actionable `help more` pointer if the full set won't fit.
mod render_status_footer;
pub(crate) use render_status_footer::render_status_footer;

pub(in crate::renderer) use super::*;

mod siblings;
pub(crate) use siblings::*;
mod items_2;
mod keybindings;
mod push_view_keybindings;
/// Render the bottom keybind row to match `design/mockups/_shared.jsx::footer`:
///   `<key>` in accent, `<hint>` in muted, three-space separator between
///   pairs.  Keys flow left-to-right and the row is truncated, with an
///   actionable `help more` pointer if the full set won't fit.
mod render_status_footer;
pub(crate) use keybindings::keybindings;
pub(crate) use push_view_keybindings::push_view_keybindings;
pub(crate) use render_status_footer::render_status_footer;

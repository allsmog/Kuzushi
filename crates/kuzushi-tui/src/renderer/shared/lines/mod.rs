pub(in crate::renderer) use super::*;

/// Catalog category divider that embeds the section blurb on the rule line:
///   `── OFFENSE find vulnerabilities by … ──────────`
/// Mirrors `catHead` in `design/mockups/catalog.jsx`.

/// Inline keybind hint matching `keybindings_line` shape:
///
///   ` <key> <hint>   <key> <hint>   …`
///   accent  muted    accent  muted
///                 · 3-space separator
///
/// Used for in-panel keybind footers (prompts editor, actor detail,
/// etc.) where a full `render_keybind_footer` rule isn't appropriate
/// but the operator still needs the local key reference.

/// Empty-state panel matching `design/mockups/empty-states.jsx::panel`:
///
/// ```text
///        ∅  no findings yet
///           kuzushi keeps the ledger in .kuzushi/v2/findings.sqlite3.
///           nothing has been promoted on this workspace.
///
///        ▸ scan          umbrella SAST · semgrep + secrets + agentic
///        ▸ context build build the snapshot first if you have time
/// ```
///
/// `glyph_label` is rendered with the ∅ glyph in subtle and the label
/// in muted.  `explanations` are muted prose lines.  `ctas` are
/// (command, blurb) pairs rendered with `▸` warn glyph + c-accent
/// command + c-muted blurb.  Caller supplies the section header
/// (typically `divider("FINDINGS · empty", width)`).

/// Render a "next-action" hint line as accent-tinted commands separated
/// by subtle middots, matching how `design/mockups/_shared.jsx`
/// next-action lines are typically painted (e.g. CTA rows in
/// `empty-states.jsx`, `auth.jsx`, `workspace.jsx`):
///
///   `kb [module] · attach <path> · detach <id>`
///   ───────────   ─────────────   ──────────────
///   accent        accent          accent
///         · subtle separators

/// Section header matching `design/mockups/_shared.jsx::sectionHeader()`:
///
///   ` ── LABEL ──────────────────...─`
///
/// Same shape as `divider` so every section title in the shell reads as
/// one consistent rule.  Kept as a separate function (rather than calling
/// `divider`) so the 12+ call sites don't all churn — if the two ever
/// diverge again the design intent stays explicit at each site.  Auto-
/// uppercases the label to mirror the prior heading-style convention.
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_2;
mod section_header_line;
pub(crate) use items_1::blank;
pub(crate) use items_1::category_divider;
pub(crate) use items_1::detail;
pub(crate) use items_1::divider;
pub(crate) use items_1::keybind_hint_line;
pub(crate) use items_2::empty_state_panel;
pub(crate) use items_2::indent;
pub(crate) use items_2::next_action_line;
pub(crate) use section_header_line::section_header_line;

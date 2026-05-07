use super::*;

pub(in crate::renderer) fn detail(key: &str, value: &str) -> Line<'static> {
    // Mockup `kv(key, val, …)` from `design/mockups/config.jsx` /
    // `workspace.jsx` puts the key in c-muted and the value in c-primary
    // (and pads the key to a fixed column for alignment). The Ratatui
    // `detail` was emitting a label-color (bold blue) key + default-style
    // value, which read as a section header rather than a kv row. Use
    // muted+primary so detail rows blend into the mockup's denser feel.
    let key_pad = 18usize;
    let key_padded = if key.chars().count() >= key_pad {
        format!("{key} ")
    } else {
        let pad_chars = key_pad - key.chars().count();
        format!("{key}{}", " ".repeat(pad_chars + 1))
    };
    Line::from(vec![
        Span::styled(key_padded, theme::muted()),
        Span::styled(value.to_string(), theme::primary()),
    ])
}

pub(in crate::renderer) fn divider(title: &str, width: u16) -> Line<'static> {
    // `design/mockups/_shared.jsx::sectionHeader` lays the rule out
    // left-aligned: ` ── LABEL ────...────`. The TUI used to center the
    // label between two rules, which read as a heavy decorative bar that
    // didn't match the lightweight muscle-memory feel of the mockups.
    let safe_width = width.max(8) as usize;
    let lead = "── ";
    let label = format!("{title} ");
    let used = 1 + lead.chars().count() + label.chars().count();
    let fill = safe_width.saturating_sub(used).max(1);
    Line::from(vec![
        Span::raw(" "),
        Span::styled(lead.to_string(), theme::subtle()),
        Span::styled(label, theme::label()),
        Span::styled(theme::RULE_CHAR.repeat(fill), theme::subtle()),
    ])
}

/// Catalog category divider that embeds the section blurb on the rule line:
///   `── OFFENSE find vulnerabilities by … ──────────`
/// Mirrors `catHead` in `design/mockups/catalog.jsx`.
pub(in crate::renderer) fn category_divider(name: &str, blurb: &str, width: u16) -> Line<'static> {
    let safe_width = width.max(8) as usize;
    let lead = "── ";
    let label = format!("{name} ");
    let blurb_text = format!("{blurb} ");
    let used = lead.chars().count() + label.chars().count() + blurb_text.chars().count();
    let fill = safe_width.saturating_sub(used).max(1);
    Line::from(vec![
        Span::styled(lead.to_string(), theme::subtle()),
        Span::styled(label, theme::label()),
        Span::styled(blurb_text, theme::muted()),
        Span::styled(theme::RULE_CHAR.repeat(fill), theme::subtle()),
    ])
}

pub(in crate::renderer) fn blank() -> Line<'static> {
    Line::raw("")
}

pub(in crate::renderer) fn muted(value: &str) -> Line<'static> {
    styled(value, theme::muted())
}

pub(in crate::renderer) fn styled(value: &str, style: Style) -> Line<'static> {
    Line::styled(value.to_string(), style)
}

/// Inline keybind hint matching `keybindings_line` shape:
///
///   ` <key> <hint>   <key> <hint>   …`
///   accent  muted    accent  muted
///                 · 3-space separator
///
/// Used for in-panel keybind footers (prompts editor, actor detail,
/// etc.) where a full `render_keybind_footer` rule isn't appropriate
/// but the operator still needs the local key reference.
pub(in crate::renderer) fn keybind_hint_line(pairs: &[(&str, &str)]) -> Line<'static> {
    let mut spans: Vec<Span<'static>> = vec![Span::raw(" ")];
    for (i, (key, hint)) in pairs.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("   "));
        }
        spans.push(Span::styled((*key).to_string(), theme::accent()));
        spans.push(Span::raw(" "));
        spans.push(Span::styled((*hint).to_string(), theme::muted()));
    }
    Line::from(spans)
}

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
pub(in crate::renderer) fn empty_state_panel(
    glyph_label: &str,
    explanations: &[&str],
    ctas: &[(&str, &str)],
) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(Line::from(vec![
        Span::raw("       "),
        Span::styled("∅  ", theme::subtle()),
        Span::styled(glyph_label.to_string(), theme::muted()),
    ]));
    for explanation in explanations {
        lines.push(Line::from(vec![
            Span::raw("       "),
            Span::styled((*explanation).to_string(), theme::muted()),
        ]));
    }
    if !ctas.is_empty() {
        lines.push(blank());
    }
    for (cmd, blurb) in ctas {
        // 22-char command pad keeps the blurbs visually aligned across
        // CTA rows (matches the mockup's fixed indent + spacing).
        let cmd_padded = if cmd.chars().count() >= 22 {
            format!("{cmd}  ")
        } else {
            format!("{cmd}{}", " ".repeat(22 - cmd.chars().count()))
        };
        lines.push(Line::from(vec![
            Span::raw("       "),
            Span::styled("▸ ", theme::warn()),
            Span::styled(cmd_padded, theme::accent()),
            Span::styled((*blurb).to_string(), theme::muted()),
        ]));
    }
    lines
}

/// Render a "next-action" hint line as accent-tinted commands separated
/// by subtle middots, matching how `design/mockups/_shared.jsx`
/// next-action lines are typically painted (e.g. CTA rows in
/// `empty-states.jsx`, `auth.jsx`, `workspace.jsx`):
///
///   `kb [module] · attach <path> · detach <id>`
///   ───────────   ─────────────   ──────────────
///   accent        accent          accent
///         · subtle separators
pub(in crate::renderer) fn command_list_line(commands: &[&str], width: usize) -> Line<'static> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut used = 0usize;
    for (i, cmd) in commands.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" · ".to_string(), theme::subtle()));
            used += 3;
        }
        let cmd_chars = cmd.chars().count();
        if used + cmd_chars > width {
            spans.push(Span::styled("…".to_string(), theme::subtle()));
            break;
        }
        spans.push(Span::styled((*cmd).to_string(), theme::accent()));
        used += cmd_chars;
    }
    Line::from(spans)
}

pub(in crate::renderer) fn indent(line: Line<'static>, spaces: usize) -> Line<'static> {
    let mut spans = vec![Span::raw(" ".repeat(spaces))];
    spans.extend(line.spans);
    Line::from(spans)
}

pub(in crate::renderer) fn next_action_line(text: &str, width: usize) -> Line<'static> {
    let available = width.saturating_sub(8);
    let fitted = fit(text, available);
    // Mirror the mockup's c-warn / c-primary / c-accent / c-muted split for
    // the catalog NEXT line (see `design/mockups/catalog.jsx`):
    //   ▸ NEXT  Run sast:scan against ~/work/acme-checkout — never run …
    //   ----    --- --------- ----------------------------- -------------
    //   warn    pri accent    primary                       muted
    // Tool name accent: detect a `Run <tool> ` prefix and split off the
    // identifier so an operator's eye lands on the actual command they're
    // about to dispatch.  Em-dash split: any ambient context after ` — `
    // (run history, finding count) reads softer than the imperative.
    let mut spans: Vec<Span<'static>> = vec![Span::styled("▸ NEXT ", theme::warn())];

    // Split at em-dash first so the muted suffix is always its own span.
    let (head, tail_with_dash) = match fitted.find(" — ") {
        Some(idx) => (&fitted[..idx], Some(&fitted[idx..])),
        None => (fitted.as_str(), None),
    };

    // Within the imperative head, detect `Run <tool> ` and accent the tool.
    if let Some(rest) = head.strip_prefix("Run ") {
        if let Some(space_idx) = rest.find(' ') {
            let tool = &rest[..space_idx];
            let after = &rest[space_idx..];
            spans.push(Span::styled("Run ".to_string(), theme::primary()));
            spans.push(Span::styled(tool.to_string(), theme::accent()));
            spans.push(Span::styled(after.to_string(), theme::primary()));
        } else {
            // `Run <single-word>` with no trailing context — accent it all.
            spans.push(Span::styled("Run ".to_string(), theme::primary()));
            spans.push(Span::styled(rest.to_string(), theme::accent()));
        }
    } else {
        spans.push(Span::styled(head.to_string(), theme::primary()));
    }

    if let Some(tail) = tail_with_dash {
        spans.push(Span::styled(tail.to_string(), theme::muted()));
    }
    Line::from(spans)
}

/// Section header matching `design/mockups/_shared.jsx::sectionHeader()`:
///
///   ` ── LABEL ──────────────────...─`
///
/// Same shape as `divider` so every section title in the shell reads as
/// one consistent rule.  Kept as a separate function (rather than calling
/// `divider`) so the 12+ call sites don't all churn — if the two ever
/// diverge again the design intent stays explicit at each site.  Auto-
/// uppercases the label to mirror the prior heading-style convention.
pub(in crate::renderer) fn section_header_line(label: &str, width: u16) -> Line<'static> {
    let safe_width = width.max(8) as usize;
    let lead = "── ";
    let label_text = format!("{} ", label.to_uppercase());
    let used = 1 + lead.chars().count() + label_text.chars().count();
    let fill = safe_width.saturating_sub(used).max(1);
    Line::from(vec![
        Span::raw(" "),
        Span::styled(lead.to_string(), theme::subtle()),
        Span::styled(label_text, theme::label()),
        Span::styled(theme::RULE_CHAR.repeat(fill), theme::subtle()),
    ])
}

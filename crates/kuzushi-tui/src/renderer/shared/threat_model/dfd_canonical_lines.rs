use super::*;

// Every box, wall, corner, junction, and arrow is placed on one shared column
// grid so the diagram aligns by construction — the previous hand-tuned space
// runs drifted 1-2 columns per row and the boxes never closed square.
const BOX_W: usize = 12; // ┌ + 10 interior + ┐
const B1: usize = 3;
const B2: usize = B1 + BOX_W + 9; // 24
const B3: usize = B2 + BOX_W + 9; // 45
// Flow drops from box 2's centre — must equal the ┬ column in `junction_border`
// (└ + (inner/2 - 1) dashes + ┬), i.e. B2 + 1 + (inner/2 - 1) = B2 + inner/2.
const JUNCTION: usize = B2 + (BOX_W - 2) / 2;

pub(crate) fn dfd_canonical_lines() -> Vec<Line<'static>> {
    let sub = theme::subtle();
    let acc = theme::accent();
    let mut_ = theme::muted();
    let warn = theme::warn();
    vec![
        // Top row of three boxes: external entity ──► process ──► data store.
        placed(&[(B1, top_border(), sub), (B2, top_border(), sub), (B3, top_border(), sub)]),
        placed(&[
            (B1, boxed_cell("user"), sub_named(sub, acc)),
            (B1 + BOX_W + 2, "─http─►".into(), sub),
            (B2, boxed_cell("api edge"), sub_named(sub, acc)),
            (B2 + BOX_W + 3, "─sql─►".into(), sub),
            (B3, boxed_cell("postgres"), sub_named(sub, acc)),
        ]),
        placed(&[
            (B1, boxed_cell("(browser)"), sub_named(sub, mut_)),
            (B2, boxed_cell("(nginx)"), sub_named(sub, mut_)),
            (B3, boxed_cell("(primary)"), sub_named(sub, mut_)),
        ]),
        placed(&[
            (B1, bottom_border(), sub),
            (B2, junction_border(), sub),
            (B3, bottom_border(), sub),
        ]),
        // Flow down from box 2 across the trust boundary to the worker pool.
        placed(&[(JUNCTION, "│".into(), sub), (JUNCTION + 2, "plaintext PII".into(), warn)]),
        placed(&[(JUNCTION, "▼".into(), sub)]),
        placed(&[(B2, top_border(), sub)]),
        placed(&[(B2, boxed_cell("worker"), sub_named(sub, acc))]),
        placed(&[(B2, boxed_cell("(rabbitmq)"), sub_named(sub, mut_))]),
        placed(&[(B2, bottom_border(), sub)]),
    ]
}

fn top_border() -> String {
    format!("┌{}┐", "─".repeat(BOX_W - 2))
}

fn bottom_border() -> String {
    format!("└{}┘", "─".repeat(BOX_W - 2))
}

fn junction_border() -> String {
    // └───┬────┘ — the ┬ sits under the box centre so the flow line lands square.
    let inner = BOX_W - 2;
    let left = inner / 2 - 1;
    format!("└{}┬{}┘", "─".repeat(left), "─".repeat(inner - left - 1))
}

fn boxed_cell(label: &str) -> String {
    // │ centred-label │ at a fixed interior width so every wall lines up.
    let inner = BOX_W - 2;
    let label: String = label.chars().take(inner).collect();
    let pad = inner - label.chars().count();
    let left = pad / 2;
    format!("│{}{}{}│", " ".repeat(left), label, " ".repeat(pad - left))
}

// Box cells carry a subtle wall colour, but the label inside reads as the named
// node (accent) or its detail (muted). A single span keeps the grid honest, so
// the whole cell takes one style; the wall/label split is intentionally dropped
// in favour of guaranteed alignment.
fn sub_named(_wall: ratatui::style::Style, label: ratatui::style::Style) -> ratatui::style::Style {
    label
}

fn placed(cells: &[(usize, String, ratatui::style::Style)]) -> Line<'static> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut col = 0usize;
    for (start, text, style) in cells {
        if *start > col {
            spans.push(Span::raw(" ".repeat(start - col)));
            col = *start;
        }
        col += text.chars().count();
        spans.push(Span::styled(text.clone(), *style));
    }
    Line::from(spans)
}

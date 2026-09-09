use super::*;
use pulldown_cmark::Alignment;

type Cell = Vec<Span<'static>>;
type Row = Vec<Cell>;

pub(super) fn render(
    nodes: &[Node<'_>],
    alignments: &[Alignment],
    width: usize,
) -> Vec<Line<'static>> {
    let rows: Vec<Row> = nodes.iter().filter_map(table_row).collect();
    let columns = alignments.len();
    if columns == 0 {
        return Vec::new();
    }
    if width < columns.saturating_mul(13).saturating_add(1) {
        return stacked(&rows, width);
    }
    grid(&rows, alignments, width)
}

fn table_row(node: &Node<'_>) -> Option<Row> {
    let Node::Branch(Tag::TableHead | Tag::TableRow, cells) = node else {
        return None;
    };
    Some(
        cells
            .iter()
            .filter_map(|node| {
                let Node::Branch(Tag::TableCell, children) = node else {
                    return None;
                };
                Some(inline::spans(children, Style::default()))
            })
            .collect(),
    )
}

fn stacked(rows: &[Row], width: usize) -> Vec<Line<'static>> {
    let Some(header) = rows.first() else {
        return Vec::new();
    };
    if rows.len() == 1 {
        return header
            .iter()
            .flat_map(|cell| wrap::lines(cell.clone(), width, true))
            .collect();
    }
    rows.iter()
        .skip(1)
        .enumerate()
        .flat_map(|(index, row)| {
            let mut lines = vec![Line::from(Span::styled(
                format!("Row {}", index + 1),
                modifier(Modifier::DIM),
            ))];
            lines.extend(stacked_cells(header, row, width));
            lines.push(Line::default());
            lines
        })
        .collect()
}

fn stacked_cells(header: &Row, row: &Row, width: usize) -> Vec<Line<'static>> {
    row.iter()
        .enumerate()
        .flat_map(|(index, cell)| {
            let mut label = header.get(index).cloned().unwrap_or_default();
            for span in &mut label {
                span.style = span.style.add_modifier(Modifier::BOLD);
            }
            label.push(Span::raw(": "));
            label.extend(cell.clone());
            wrap::lines(label, width, true)
        })
        .collect()
}

fn grid(rows: &[Row], alignments: &[Alignment], width: usize) -> Vec<Line<'static>> {
    let available = width.saturating_sub(alignments.len() + 1);
    let sizes: Vec<_> = (0..alignments.len())
        .map(|index| {
            available / alignments.len() + usize::from(index < available % alignments.len())
        })
        .collect();
    let mut lines = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        lines.extend(grid_row(row, &sizes, alignments, index == 0));
        if index == 0 {
            lines.push(grid_rule(&sizes));
        }
    }
    lines
}

fn grid_row(
    row: &Row,
    sizes: &[usize],
    alignments: &[Alignment],
    header: bool,
) -> Vec<Line<'static>> {
    let cells: Vec<_> = sizes
        .iter()
        .enumerate()
        .map(|(index, size)| {
            wrap::lines(
                row.get(index).cloned().unwrap_or_default(),
                size.saturating_sub(2),
                true,
            )
        })
        .collect();
    let height = cells.iter().map(Vec::len).max().unwrap_or(1);
    (0..height)
        .map(|line| grid_line(&cells, sizes, alignments, line, header))
        .collect()
}

fn grid_line(
    cells: &[Vec<Line<'static>>],
    sizes: &[usize],
    alignments: &[Alignment],
    line: usize,
    header: bool,
) -> Line<'static> {
    let mut spans = vec![Span::raw("│")];
    for (index, size) in sizes.iter().enumerate() {
        let content = cells[index].get(line).cloned().unwrap_or_default();
        spans.extend(padded_cell(content, *size, alignments[index], header));
        spans.push(Span::raw("│"));
    }
    Line::from(spans)
}

fn padded_cell(
    mut line: Line<'static>,
    width: usize,
    alignment: Alignment,
    header: bool,
) -> Vec<Span<'static>> {
    let padding = width.saturating_sub(line.width() + 2);
    let left = match alignment {
        Alignment::Right => padding,
        Alignment::Center => padding / 2,
        _ => 0,
    };
    if header {
        for span in &mut line.spans {
            span.style = span.style.add_modifier(Modifier::BOLD);
        }
    }
    line.spans.insert(0, Span::raw(" ".repeat(left + 1)));
    line.spans.push(Span::raw(" ".repeat(padding - left + 1)));
    line.spans
}

fn grid_rule(sizes: &[usize]) -> Line<'static> {
    Line::from(format!(
        "├{}┤",
        sizes
            .iter()
            .map(|size| "─".repeat(*size))
            .collect::<Vec<_>>()
            .join("┼")
    ))
}

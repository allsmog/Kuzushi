pub(in crate::renderer) use super::*;

const TABLE_COLUMN_SEPARATOR: &str = "  ";

pub(crate) fn table_gap_width(columns: usize) -> usize {
    display_width(TABLE_COLUMN_SEPARATOR) * columns.saturating_sub(1)
}

pub(crate) fn fit_table_widths<const N: usize>(
    total: usize,
    preferred: [usize; N],
    minimums: [usize; N],
) -> [usize; N] {
    let budget = total.saturating_sub(table_gap_width(N));
    let mut widths = preferred;
    shrink_table_widths(&mut widths, &minimums, budget);
    let remaining = budget.saturating_sub(widths.iter().sum());
    if let Some(last) = widths.last_mut() {
        *last += remaining;
    }
    widths
}

fn shrink_table_widths(widths: &mut [usize], minimums: &[usize], budget: usize) {
    while widths.iter().sum::<usize>() > budget {
        let preferred = widths
            .iter()
            .zip(minimums)
            .enumerate()
            .filter(|(_, (width, minimum))| **width > **minimum)
            .max_by_key(|(_, (width, minimum))| (**width).saturating_sub(**minimum))
            .map(|(index, _)| index);
        let fallback = widths
            .iter()
            .enumerate()
            .filter(|(_, width)| **width > 0)
            .max_by_key(|(_, width)| **width)
            .map(|(index, _)| index);
        let Some(index) = preferred.or(fallback) else {
            break;
        };
        widths[index] -= 1;
    }
}

#[cfg(test)]
pub(crate) fn table_width(widths: &[usize]) -> usize {
    let visible_columns = widths.iter().filter(|width| **width > 0).count();
    widths.iter().sum::<usize>() + table_gap_width(visible_columns)
}

pub(crate) fn module_table_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    let id = if total < 72 { 14 } else { 22 };
    let gaps = table_gap_width(2);
    let description = total.saturating_sub(id + gaps).max(16);
    fit_table_widths(total, [id, description], [8, 8]).to_vec()
}

pub(crate) fn table_header(values: &[&str], widths: &[usize]) -> Line<'static> {
    // Mockup column headers wear `c-label` (bold blue), see e.g.
    // `design/mockups/findings.jsx::heads` and `tools.jsx::heads`.
    Line::styled(table_text(values, widths), theme::label())
}

pub(crate) fn table_row(values: &[&str], widths: &[usize]) -> Line<'static> {
    // Same colour split as `aligned_row` so help/options/findings tables
    // share the mockup tint:
    //   col 0 → c-accent (identifier), middle → c-primary, last → c-muted
    let mut spans = Vec::new();
    let last = values.len().saturating_sub(1);
    let mut rendered = 0;
    for (index, (value, width)) in values.iter().zip(widths).enumerate() {
        if *width == 0 {
            continue;
        }
        if rendered > 0 {
            spans.push(Span::raw(TABLE_COLUMN_SEPARATOR));
        }
        let style = if index == 0 {
            theme::accent()
        } else if values.len() > 2 && index == last {
            theme::muted()
        } else {
            theme::primary()
        };
        spans.push(Span::styled(pad(value, *width), style));
        rendered += 1;
    }
    Line::from(spans)
}

pub(crate) fn table_text(values: &[&str], widths: &[usize]) -> String {
    values
        .iter()
        .zip(widths)
        .filter(|(_, width)| **width > 0)
        .map(|(value, width)| pad(value, *width))
        .collect::<Vec<_>>()
        .join(TABLE_COLUMN_SEPARATOR)
}

pub(crate) fn row(values: &[String]) -> Line<'static> {
    let mut spans = Vec::with_capacity(values.len().saturating_mul(2).saturating_sub(1));
    for (index, value) in values.iter().enumerate() {
        let style = if index == 0 {
            theme::accent()
        } else {
            Style::default()
        };
        spans.push(Span::styled(value.clone(), style));
        if index + 1 < values.len() {
            spans.push(Span::styled(TABLE_COLUMN_SEPARATOR, style));
        }
    }
    Line::from(spans)
}

pub(crate) fn aligned_header(values: &[&str], widths: &[usize]) -> Line<'static> {
    Line::from(aligned_spans(values, widths, |_| theme::label()))
}

pub(crate) fn aligned_row(values: &[String], widths: &[usize]) -> Line<'static> {
    // Mockup table rows (`design/mockups/tools.jsx`, `modules.jsx`,
    // `cost.jsx`, etc.) consistently put the first column (the
    // identifier) in c-accent, with subsequent value columns in
    // c-primary and metadata columns (last when present) in c-muted.
    // The Ratatui `aligned_row` was leaving columns 1+ in
    // `Style::default()`, which renders as terminal default white —
    // visibly distinct from the mockup's softer c-primary tint.
    let last = values.len().saturating_sub(1);
    Line::from(aligned_spans(values, widths, |index| {
        if index == 0 {
            theme::accent()
        } else if values.len() > 2 && index == last {
            theme::muted()
        } else {
            theme::primary()
        }
    }))
}

fn aligned_spans<T, F>(values: &[T], widths: &[usize], mut styled: F) -> Vec<Span<'static>>
where
    T: AsRef<str>,
    F: FnMut(usize) -> Style,
{
    let count = values
        .iter()
        .zip(widths)
        .filter(|(_, width)| **width > 0)
        .count();
    let mut spans = Vec::with_capacity(count.saturating_mul(2).saturating_sub(1));
    let mut rendered = 0;
    for (index, (value, width)) in values.iter().zip(widths.iter()).enumerate() {
        if *width == 0 {
            continue;
        }
        let style = styled(index);
        spans.push(Span::styled(
            pad(&fit(value.as_ref(), *width), *width),
            style,
        ));
        rendered += 1;
        if rendered < count {
            spans.push(Span::styled(TABLE_COLUMN_SEPARATOR, style));
        }
    }
    spans
}

#[cfg(test)]
mod tests {
    use super::{aligned_header, aligned_row, fit_table_widths, row, table_gap_width, table_width};
    use crate::renderer::shared::text::display_width;

    fn line_width(line: &ratatui::text::Line<'_>) -> usize {
        line.spans
            .iter()
            .map(|span| display_width(span.content.as_ref()))
            .sum()
    }

    #[test]
    fn aligned_helpers_only_separate_columns_between_values() {
        let widths = [4, 5];
        let header = aligned_header(&["名", "state"], &widths);
        let table_row = aligned_row(&["界".to_string(), "ready".to_string()], &widths);
        let unaligned = row(&["界".to_string(), "ready".to_string()]);

        assert_eq!(line_width(&header), 11);
        assert_eq!(line_width(&table_row), 11);
        assert_eq!(line_width(&unaligned), 9);
        assert_eq!(table_gap_width(2), 2);
        assert_eq!(table_gap_width(5), 8);
    }

    #[test]
    fn shrinkable_columns_honor_narrow_area_budgets() {
        for width in [40, 60, 80] {
            let widths = fit_table_widths(width, [18, 24, 30], [8, 8, 6]);

            assert_eq!(table_width(&widths), width);
            assert!(widths.iter().all(|column| *column > 0));
        }
    }

    #[test]
    fn fitting_below_the_separator_budget_removes_empty_columns() {
        let widths = fit_table_widths(1, [4, 4, 4], [1, 1, 1]);

        assert!(table_width(&widths) <= 1);
        assert!(line_width(&aligned_header(&["a", "b", "c"], &widths)) <= 1);
    }
}

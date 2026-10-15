use super::*;
use crate::ui_view_models::status_footer_model;

pub(crate) fn render_status_footer(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }

    let model = status_footer_model(app);
    let compact = area.width < 80;
    let left = if compact {
        &model.compact_left_segments
    } else {
        &model.left_segments
    };
    let right = footer_segments(
        &model.right_segments,
        &model.compact_right_segments,
        compact,
    );
    let text = status_footer_text(left, right, area.width as usize);
    frame.render_widget(Paragraph::new(Line::styled(text, theme::primary())), area);
}

fn footer_segments(wide: &[String], compact: &[String], use_compact: bool) -> String {
    join_segments(if use_compact { compact } else { wide })
}

/// Preserve the leading policy control; trim detail after the finding count
/// when both sides do not fit. The model orders lower-priority facts after it.
fn status_footer_text(left: &[String], right: String, width: usize) -> String {
    let Some((first, rest)) = left.split_first() else {
        return fit(&right, width);
    };
    let first = fit(first, width);
    let remaining = width.saturating_sub(display_width(&first) + 3);
    if remaining == 0 {
        return first;
    }
    let right = fit(&right, remaining);
    let detail_budget = remaining.saturating_sub(display_width(&right) + 1);
    let first_detail_width = rest.first().map_or(0, |segment| display_width(segment));
    let details = if detail_budget >= first_detail_width {
        join_segments(rest)
    } else {
        String::new()
    };
    format!(
        "{first} · {}",
        justify_prefer_right(details, right, remaining)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_stale_notice_survives_beside_the_longest_ceiling_and_finding_count() {
        let left = vec!["⛭ autonomy:review ⚠ stale".into()];
        let text = status_footer_text(&left, "0 findings".into(), 40);
        assert!(text.contains("autonomy:review"));
        assert!(text.contains("⚠ stale"));
        assert!(text.contains("0 findings"));
        assert!(display_width(&text) <= 40);
    }

    #[test]
    fn status_footer_preserves_operator_ceiling_and_finding_count_at_every_width() {
        let left = vec![
            "⛭ autonomy:review ⚠".to_string(),
            "shell route".to_string(),
            "notify:unavailable · focus unknown".to_string(),
        ];
        let right = "6 findings · 1 C · 2 H · 2 M".to_string();
        for width in [40, 60, 80, 96, 120, 160] {
            let line = status_footer_text(&left, right.clone(), width);
            assert!(line.contains("⛭ autonomy:review ⚠"), "{width}: {line}");
            assert!(line.contains("6 findings"), "{width}: {line}");
            assert!(display_width(&line) <= width);
        }
    }
}

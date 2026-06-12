use super::*;
use crate::ui_view_models::notice_banner_model;
use crate::NoticeSeverity;

/// Tallest the banner is allowed to grow. Three lines holds every scan/tool
/// error remedy we emit today; anything longer ends with an ellipsis.
pub(crate) const NOTICE_BANNER_MAX_LINES: usize = 3;

const DISMISS_HINT: &str = "  Esc dismiss";

pub(crate) fn render_notice_banner(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let lines = notice_banner_lines(app, area.width, area.height as usize);
    if lines.is_empty() {
        return;
    }
    frame.render_widget(Paragraph::new(lines), area);
}

/// How many rows the banner needs at `width`, capped by `max_lines`. The
/// section-slot layout calls this so the reserved height always matches what
/// `render_notice_banner` draws.
pub(crate) fn notice_banner_line_count(app: &ShellApp, width: u16, max_lines: usize) -> usize {
    notice_banner_lines(app, width, max_lines).len()
}

/// Chip-style banner mirroring the rate-limit banner: a coloured chip pops
/// first, then source + message. Error is red, Warn is amber. Long messages
/// wrap onto continuation lines instead of truncating — error remedies are
/// the one thing the operator must be able to read in full.
fn notice_banner_lines(app: &ShellApp, width: u16, max_lines: usize) -> Vec<Line<'static>> {
    let Some(notice) = notice_banner_model(app) else {
        return Vec::new();
    };
    let (chip, chip_style) = match notice.severity {
        NoticeSeverity::Error => (" ERROR ", theme::danger()),
        NoticeSeverity::Warn => (" NOTICE ", theme::warn()),
        NoticeSeverity::Success => (" DONE ", theme::success()),
    };
    let prefix_width = 1 + chip.len() + 2 + notice.source.chars().count() + 3;
    let budget = (width as usize)
        .saturating_sub(prefix_width + DISMISS_HINT.len())
        .max(16);
    let cap = max_lines.clamp(1, NOTICE_BANNER_MAX_LINES);
    let chunks = capped_message_chunks(&notice.message, budget, cap);

    let mut lines = Vec::with_capacity(chunks.len());
    for (index, chunk) in chunks.iter().enumerate() {
        let mut spans = if index == 0 {
            vec![
                Span::raw(" "),
                Span::styled(chip, chip_style),
                Span::raw("  "),
                Span::styled(notice.source.clone(), theme::primary()),
                Span::styled(" · ", theme::subtle()),
                Span::styled(chunk.clone(), theme::muted()),
            ]
        } else {
            vec![
                Span::raw(" ".repeat(prefix_width)),
                Span::styled(chunk.clone(), theme::muted()),
            ]
        };
        if index == chunks.len() - 1 {
            spans.push(Span::styled(DISMISS_HINT, theme::subtle()));
        }
        lines.push(Line::from(spans));
    }
    lines
}

fn capped_message_chunks(message: &str, budget: usize, max_lines: usize) -> Vec<String> {
    let mut chunks = wrap_text(message, budget);
    if chunks.is_empty() {
        chunks.push(String::new());
    }
    if chunks.len() > max_lines {
        chunks.truncate(max_lines);
        if let Some(last) = chunks.last_mut() {
            last.push('…');
        }
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;

    fn app_with_error(message: &str) -> ShellApp {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_error_notice("scan", message.to_string());
        app
    }

    fn rendered_text(lines: &[Line<'_>]) -> String {
        lines
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn short_error_stays_on_one_line_with_dismiss_hint() {
        let app = app_with_error("semgrep missing");
        let lines = notice_banner_lines(&app, 120, NOTICE_BANNER_MAX_LINES);

        assert_eq!(lines.len(), 1);
        let text = rendered_text(&lines);
        assert!(text.contains("semgrep missing"));
        assert!(text.contains("Esc dismiss"));
    }

    #[test]
    fn long_error_wraps_so_the_full_remedy_is_readable() {
        let message = "semgrep: could not find scanner binary \"semgrep\". Install Semgrep \
                       (for example `pipx install semgrep`) or block the task. Next: tasks, \
                       task block semgrep, or run semgrep:scan with an explicit binary path";
        let app = app_with_error(message);
        let lines = notice_banner_lines(&app, 120, NOTICE_BANNER_MAX_LINES);

        assert!(lines.len() > 1, "long remedy must wrap, not truncate");
        let text = rendered_text(&lines);
        assert!(
            text.contains("explicit binary path"),
            "tail of the remedy must survive wrapping:\n{text}"
        );
        assert!(text.ends_with("  Esc dismiss"));
    }

    #[test]
    fn pathological_message_caps_at_three_lines_with_ellipsis() {
        let app = app_with_error(&"word ".repeat(400));
        let lines = notice_banner_lines(&app, 80, NOTICE_BANNER_MAX_LINES);

        assert_eq!(lines.len(), NOTICE_BANNER_MAX_LINES);
        let text = rendered_text(&lines);
        assert!(text.contains('…'));
        assert!(text.contains("Esc dismiss"));
    }

    #[test]
    fn line_count_matches_rendered_lines() {
        let message = "a long failure explanation that needs to wrap across the banner because \
                       it carries the remedy the operator has to read in full to recover";
        let app = app_with_error(message);

        assert_eq!(
            notice_banner_line_count(&app, 90, NOTICE_BANNER_MAX_LINES),
            notice_banner_lines(&app, 90, NOTICE_BANNER_MAX_LINES).len()
        );
    }
}

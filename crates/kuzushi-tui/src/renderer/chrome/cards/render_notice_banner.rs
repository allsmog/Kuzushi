use super::*;
use crate::ui_view_models::{notice_banner_model, NoticeBannerModel};
use crate::NoticeSeverity;

/// A preview stays bounded; overflow points to the complete transcript entry.
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

fn notice_banner_lines(app: &ShellApp, width: u16, max_lines: usize) -> Vec<Line<'static>> {
    let Some(notice) = notice_banner_model(app) else {
        return Vec::new();
    };
    let width = usize::from(width);
    let cap = max_lines.clamp(1, NOTICE_BANNER_MAX_LINES);
    let single = single_notice_line(&notice);
    if single.width() <= width {
        return vec![single];
    }
    let route = complete_notice_route(app);
    if cap == 1 {
        return vec![compact_notice_header(&notice, &route, width)];
    }
    let mut lines = vec![notice_header(&notice, width)];
    lines.extend(notice_preview(&notice.message, &route, width, cap - 1));
    lines
}

fn complete_notice_route(app: &ShellApp) -> String {
    let keys = app
        .ui()
        .keymap_binding_labels("global", "command_palette", &["Ctrl+G"]);
    if keys.is_empty() {
        return "logs: full message".to_string();
    }
    format!("{} → logs", keys.join("/"))
}

fn notice_header(notice: &NoticeBannerModel, width: usize) -> Line<'static> {
    let (chip, style) = notice_chip(notice.severity);
    let hint = notice_dismiss_hint(notice.dismiss_on_escape);
    let budget = width.saturating_sub(chip.len() + hint.len() + 1);
    Line::from(vec![
        Span::styled(chip, style),
        Span::styled(
            format!(" {}", fit(&notice.source, budget)),
            theme::primary(),
        ),
        Span::styled(hint, theme::subtle()),
    ])
}

fn compact_notice_header(notice: &NoticeBannerModel, route: &str, width: usize) -> Line<'static> {
    let (chip, style) = notice_chip(notice.severity);
    let hint = notice_dismiss_hint(notice.dismiss_on_escape);
    Line::styled(fit(&format!("{chip}{hint} · {route}"), width), style)
}

fn notice_preview(message: &str, route: &str, width: usize, cap: usize) -> Vec<Line<'static>> {
    let mut chunks = wrap_text(message, width);
    if chunks.len() > cap {
        chunks.truncate(cap);
        let suffix = format!("… · {route}");
        let budget = width.saturating_sub(crate::renderer::shared::text::display_width(&suffix));
        if let Some(last) = chunks.last_mut() {
            *last = format!(
                "{}{}",
                crate::renderer::shared::text::take_columns(last, budget),
                suffix
            );
        }
    }
    chunks
        .into_iter()
        .map(|text| Line::styled(text, theme::muted()))
        .collect()
}

fn notice_chip(severity: NoticeSeverity) -> (&'static str, Style) {
    match severity {
        NoticeSeverity::Error => (" ERROR ", theme::danger()),
        NoticeSeverity::Warn => (" NOTICE ", theme::warn()),
        NoticeSeverity::Info => (" NOTICE ", theme::muted()),
        NoticeSeverity::Success => (" DONE ", theme::success()),
    }
}

fn notice_dismiss_hint(dismiss_on_escape: bool) -> &'static str {
    if dismiss_on_escape {
        DISMISS_HINT
    } else {
        ""
    }
}

fn single_notice_line(notice: &NoticeBannerModel) -> Line<'static> {
    let (chip, chip_style) = notice_chip(notice.severity);
    Line::from(vec![
        Span::raw(" "),
        Span::styled(chip, chip_style),
        Span::raw("  "),
        Span::styled(notice.source.clone(), theme::primary()),
        Span::styled(" · ", theme::subtle()),
        Span::styled(notice.message.clone(), theme::muted()),
        Span::styled(
            notice_dismiss_hint(notice.dismiss_on_escape),
            theme::subtle(),
        ),
    ])
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
    fn successful_review_receipt_uses_done_chip() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_success_notice("review", "decision saved; will carry forward");

        let lines = notice_banner_lines(&app, 110, NOTICE_BANNER_MAX_LINES);
        let text = rendered_text(&lines);

        assert!(text.contains("DONE"));
        assert!(text.contains("review · decision saved; will carry forward"));
        assert!(!text.contains("Esc dismiss"));
    }

    #[test]
    fn nonblocking_notices_do_not_advertise_escape_dismissal() {
        for success in [false, true] {
            let mut app = ShellApp::new(V2Config::default(), None);
            if success {
                app.set_success_notice("run", "completed");
            } else {
                app.set_info_notice("run", "completed");
            }
            let text = rendered_text(&notice_banner_lines(&app, 80, NOTICE_BANNER_MAX_LINES));
            assert!(text.contains("completed"));
            assert!(!text.contains("Esc dismiss"));
        }
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
        assert!(text.contains("Esc dismiss"));
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
    fn narrow_notice_keeps_dismissal_and_the_complete_message_route_in_bounds() {
        let app = app_with_error("structured output failed: Restore the missing code-analysis component: from source run cargo build --workspace; otherwise reinstall Kuzushi.");
        for cap in [1, 3] {
            let lines = notice_banner_lines(&app, 40, cap);
            assert!(lines.iter().all(|line| line.width() <= 40), "{lines:?}");
            let text = rendered_text(&lines);
            assert!(text.contains("Esc dismiss"), "{text}");
            assert!(text.contains("Ctrl+G → logs"), "{text}");
        }
    }

    #[test]
    fn narrow_notice_respects_unicode_source_and_remapped_palette() {
        let mut config = V2Config::default();
        config.operator.keybindings = vec![kuzushi_core::config::KeybindingOverrideConfig {
            context: "global".into(),
            action: "command_palette".into(),
            bindings: vec!["ctrl+y".into()],
        }];
        let mut app = ShellApp::new(config, None);
        app.set_error_notice("分析".repeat(30), "failure ".repeat(50));
        let lines = notice_banner_lines(&app, 40, 3);
        assert!(lines.iter().all(|line| line.width() <= 40), "{lines:?}");
        let text = rendered_text(&lines);
        assert!(text.contains("ctrl+y → logs"), "{text}");
        assert!(text.contains("Esc dismiss"), "{text}");
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

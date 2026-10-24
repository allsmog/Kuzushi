use crate::app::ShellApp;

pub(crate) fn matrix_result_controls(app: &ShellApp) -> Vec<String> {
    let config = app.router.campaign().batch_scan_config.as_ref();
    let selection = config.and_then(|config| config.study.matrix.pass_selection);
    if let Some(baseline) = selection {
        return vec![
            "↑↓ pass · Enter choose · Esc back".into(),
            "r refresh · R report".into(),
            if baseline {
                "Choose a completed baseline pass."
            } else {
                "Choose a recorded candidate pass."
            }
            .into(),
        ];
    }
    let position = super::matrix_result_read_limits(app).map_or_else(
        || "Reading results · Esc back".into(),
        |limits| {
            let scroll = config
                .map_or(0, |config| config.study.matrix.detail_scroll)
                .min(limits.max_scroll);
            format!(
                "Read {}-{}/{} · Esc",
                (scroll + 1).min(limits.total_lines),
                scroll.saturating_add(limits.page).min(limits.total_lines),
                limits.total_lines
            )
        },
    );
    vec![
        "↑↓ cases · Enter pass · b baseline".into(),
        "PgUp/PgDn · r refresh · R report".into(),
        position,
    ]
}

use crate::app::ShellApp;

pub(crate) fn matrix_result_controls(app: &ShellApp) -> Vec<String> {
    let config = app.router.campaign().batch_scan_config.as_ref();
    if config.is_some_and(|config| config.study.matrix.observation_key.is_some()) {
        return vec![
            "↑↓ findings · Enter review".into(),
            "PgUp/Dn · Home/End read".into(),
            "r refresh · Esc cases".into(),
            reading_position(app, config),
        ];
    }
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
    vec![
        "↑↓ cases · f findings".into(),
        "Enter pass · b baseline".into(),
        "PgUp/PgDn · r refresh · R report".into(),
        reading_position(app, config),
    ]
}

fn reading_position(app: &ShellApp, config: Option<&crate::app::BatchScanConfig>) -> String {
    super::matrix_result_read_limits(app).map_or_else(
        || "Reading results · Esc back".into(),
        |limits| {
            let scroll = config
                .map_or(0, |config| {
                    if config.study.matrix.observation_key.is_some() {
                        config.study.matrix.observation_scroll
                    } else {
                        config.study.matrix.detail_scroll
                    }
                })
                .min(limits.max_scroll);
            format!(
                "Read {}-{}/{} · Esc",
                (scroll + 1).min(limits.total_lines),
                scroll.saturating_add(limits.page).min(limits.total_lines),
                limits.total_lines
            )
        },
    )
}

use super::{BatchScanConfig, BatchScanConfigRow};

pub(crate) fn study_read_hint(
    config: &BatchScanConfig,
    attention: bool,
    offset: usize,
    maximum: usize,
) -> String {
    if !attention && config.selected_row() == BatchScanConfigRow::Context {
        let next = config.source_view.selected.next(false).label();
        let controls = if config.detail_reader_scroll.is_some() {
            "z form · ↑↓/PgUp/Dn"
        } else {
            "z read · PgUp/Dn"
        };
        return format!("Tab {next} · {controls}");
    }
    let reading = if config.detail_reader_scroll.is_some() {
        "z form · ↑↓ scroll"
    } else {
        "↑↓ choose · z read"
    };
    format!("{reading} · PgUp/Dn {}/{}", offset + 1, maximum + 1)
}

pub(crate) fn study_controls_hint(
    row: BatchScanConfigRow,
    width: usize,
    attention: bool,
) -> &'static str {
    if attention {
        return "Esc dismiss · PgUp/Dn read";
    }
    if width < 44 {
        return "Enter · L next · r reload · Esc back";
    }
    match row {
        BatchScanConfigRow::Brief => "Enter brief · L next · r refresh · Esc back",
        BatchScanConfigRow::Context => "Enter context · L next · r refresh · Esc back",
        BatchScanConfigRow::Engines => "Enter engines · L next · r refresh · Esc back",
        BatchScanConfigRow::Launch => "Enter / L next · r refresh · Esc back",
        BatchScanConfigRow::ContextComparison => "Enter compare · L next · r refresh · Esc back",
        BatchScanConfigRow::ContextCases => "Enter cases · L next · r refresh · Esc back",
        _ => "Enter edit · L next · r refresh · Esc back",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_tabs_and_read_controls_fit_the_narrowest_viewport() {
        let target = tempfile::tempdir().unwrap();
        let mut config = BatchScanConfig::load(target.path(), None);
        config.cursor = 3;
        for _ in 0..4 {
            for expanded in [false, true] {
                config.detail_reader_scroll = expanded.then_some(0);
                let hint = study_read_hint(&config, false, 0, 200);
                assert!(hint.chars().count() <= 36, "{hint}");
                assert!(hint.contains("Tab") && hint.contains("PgUp/Dn"));
                assert!(hint.contains(if expanded { "z form" } else { "z read" }));
            }
            config.source_view.selected = config.source_view.selected.next(false);
        }
    }

    #[test]
    fn study_controls_keep_refresh_and_back_visible_at_all_supported_widths() {
        for width in [36, 56, 76, 92, 116, 156] {
            for row in BatchScanConfigRow::ALL {
                let hint = study_controls_hint(row, width, false);
                assert!(hint.chars().count() <= width);
                assert!(
                    hint.contains("r re") && hint.contains("L next") && hint.contains("Esc back")
                );
            }
        }
    }

    #[test]
    fn modal_notice_keeps_dismissal_as_the_only_next_action() {
        assert_eq!(
            study_controls_hint(BatchScanConfigRow::PriorRun, 36, true),
            "Esc dismiss · PgUp/Dn read"
        );
    }
}

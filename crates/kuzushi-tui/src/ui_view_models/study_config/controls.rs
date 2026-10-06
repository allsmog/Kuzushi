use super::BatchScanConfigRow;

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
        BatchScanConfigRow::Context => "Enter context · L next · r refresh · Esc back",
        BatchScanConfigRow::Engines => "Enter engines · L next · r refresh · Esc back",
        BatchScanConfigRow::Launch => "Enter / L next · r refresh · Esc back",
        _ => "Enter edit · L next · r refresh · Esc back",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

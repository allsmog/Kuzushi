use super::*;

fn long_row() -> BatchOccurrenceRow {
    BatchOccurrenceRow {
        fold_key: "fold-key".into(), identity_id: None, identity_basis: None,
        seen: 2, completed: 3, planned: 5, failed: 1,
        severities: vec!["high".into()], locations: vec![], titles: vec![],
        fingerprints: vec!["finding-exact-identity".into()],
        run_ids: vec!["run-discovery-exact-reference-1".into(), "run-discovery-exact-reference-2".into()],
        representative_fingerprint: "finding-exact-identity".into(),
        representative_title: "Untrusted repository paths escape the configured workspace boundary".into(),
        representative_severity: "high".into(),
        representative_location: "packages/server/src/components/very-long-subsystem-name/handlers/workspace-path-handler.rs:137".into(),
    }
}

#[test]
fn title_leads_and_complete_location_identity_and_runs_survive_narrow_columns() {
    let row = long_row();
    for width in [60, 80, 120] {
        let lines = batch_occurrence_row(&row, width);
        assert!(lines[1]
            .to_string()
            .contains("high · Untrusted repository paths"));
        assert!(lines.iter().all(|line| line.width() <= width));
        let text = lines
            .iter()
            .map(|line| line.to_string().trim().to_string())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(text.contains(&row.representative_title));
        assert!(text.contains("seen 2 / completed 3"));
        assert!(text.contains("planned 5 · failed 1"));
        assert!(text.contains(&row.representative_fingerprint));
        for run in &row.run_ids {
            assert!(text.contains(run));
        }
        // A long path can wrap inside a token; every character must remain.
        assert!(text.replace(' ', "").contains(&row.representative_location));
    }
}

#[test]
fn terminal_buffer_keeps_the_title_visible_before_occurrence_metadata() {
    let row = long_row();
    let lines = batch_occurrence_row(&row, 80);
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 20)).unwrap();
    terminal
        .draw(|frame| frame.render_widget(Paragraph::new(lines), frame.area()))
        .unwrap();
    let buffer = terminal.backend().buffer();
    let rendered = format!("{buffer:?}");
    assert!(rendered.contains("high · Untrusted repository paths"));
    assert!(rendered.find("high ·").unwrap() < rendered.find("seen 2 / completed 3").unwrap());
    assert!(rendered.contains("finding-exact-identity"));
    assert!(rendered.contains("run-discovery-exact-reference-2"));
    assert!(!rendered.contains("..."));
}

#[test]
fn retained_only_observations_keep_guidance_and_provenance_at_every_width() {
    let mut row = long_row();
    row.seen = 0;
    for width in [40, 60, 80, 96, 120, 160] {
        let lines = batch_occurrence_row(&row, width);
        assert!(lines.iter().all(|line| line.width() <= width));
        let text = lines
            .iter()
            .map(|line| line.to_string().trim().to_string())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(text.contains("Retained outside completed passes"));
        assert!(text.contains("seen 0 / completed 3"));
        assert!(text.contains("run-discovery-exact-reference-1"));
    }
}

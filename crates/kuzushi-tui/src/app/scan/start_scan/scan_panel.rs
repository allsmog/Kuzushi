use super::*;

pub(crate) fn queued_scan_panel(target_root: &PathBuf, run_id: &str) -> ScanPanelState {
    ScanPanelState {
        run_id: Some(run_id.to_string()),
        target: target_root.clone(),
        stage: "queued".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queued_scan_panel_seeds_failure_handoff_run_id() {
        let temp = tempfile::tempdir().unwrap();
        let panel = queued_scan_panel(&temp.path().to_path_buf(), "scan-seeded");

        assert_eq!(panel.run_id.as_deref(), Some("scan-seeded"));
        assert!(panel.running);
    }
}

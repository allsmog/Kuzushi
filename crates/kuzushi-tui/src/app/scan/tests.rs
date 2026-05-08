#[cfg(test)]
mod tests {
    use super::super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn start_scan_reports_already_running_without_spawning_worker() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.scan = Some(ScanPanelState {
            run_id: None,
            target: temp.path().to_path_buf(),
            stage: "running".to_string(),
            findings_count: 0,
            running: true,
            abort_requested: false,
            error: None,
        });

        app.start_scan(Some(temp.path().to_path_buf()));

        assert!(app
            .log
            .iter()
            .any(|line| line.body.contains("scan already running")));
    }

    #[test]
    fn start_scan_reports_invalid_target_before_worker_spawn() {
        let temp = tempfile::tempdir().unwrap();
        let file_target = temp.path().join("not-a-directory");
        std::fs::write(&file_target, "x").unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);

        app.start_scan(Some(file_target));

        assert!(app.scan.is_none());
        assert!(app.log.iter().any(|line| line.prefix == "error"));
    }
}

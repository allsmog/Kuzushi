use super::ScanPanelState;

pub(crate) fn scan_status(scan: &ScanPanelState) -> String {
    if scan.running && scan.abort_requested {
        "abort requested: waiting for subprocess".to_string()
    } else if scan.running {
        format!("running: {}", scan.stage)
    } else {
        scan.stage.clone()
    }
}

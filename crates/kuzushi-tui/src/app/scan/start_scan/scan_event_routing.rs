use super::*;

impl ShellApp {
    pub(crate) fn apply_scan_event(&mut self, event: ScanEvent) -> Vec<ShellEffect> {
        match event {
            ScanEvent::Stage(stage) => self.apply_scan_stage(stage),
            ScanEvent::Finished { result } => self.apply_scan_result(result),
            ScanEvent::Failed { error } => self.apply_scan_failed(error),
        }
    }

    pub(crate) fn apply_scan_stage(&mut self, stage: String) -> Vec<ShellEffect> {
        if let Some(scan) = self.scan_mut() {
            scan.stage = stage.clone();
        }
        self.log("scan", stage);
        Vec::new()
    }
}

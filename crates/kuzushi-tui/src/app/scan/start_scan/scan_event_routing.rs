use super::*;

impl ShellApp {
    pub(crate) fn apply_scan_event(&mut self, event: ScanEvent) {
        match event {
            ScanEvent::Started { run_id, target } => self.apply_scan_started(run_id, target),
            ScanEvent::Stage(stage) => self.apply_scan_stage(stage),
            ScanEvent::FindingStored {
                fingerprint,
                severity,
                title,
            } => self.apply_scan_finding_stored(fingerprint, severity, title),
            ScanEvent::Finished {
                run_id,
                findings_count,
            } => self.apply_scan_finished(run_id, findings_count),
            ScanEvent::Failed { error } => self.apply_scan_failed(error),
            ScanEvent::Cancelled { run_id } => self.apply_scan_cancelled(run_id),
        }
    }

    pub(crate) fn apply_scan_started(&mut self, run_id: String, target: PathBuf) {
        if let Some(scan) = &mut self.scan {
            scan.run_id = Some(run_id.clone());
            scan.target = target;
            scan.stage = "starting scan".to_string();
            scan.abort_requested = false;
        }
        self.log("scan", format!("run {}", short_fingerprint(&run_id)));
    }

    pub(crate) fn apply_scan_stage(&mut self, stage: String) {
        if let Some(scan) = &mut self.scan {
            scan.stage = stage.clone();
        }
        self.append_scan_stage_trace(&stage);
        self.log("scan", stage);
    }

    pub(crate) fn append_scan_stage_trace(&self, stage: &str) {
        let Some(run_id) = self.scan.as_ref().and_then(|scan| scan.run_id.as_ref()) else {
            return;
        };
        let step_index = self.log.iter().filter(|line| line.prefix == "scan").count() + 1;
        append_trace_step(
            self.target.as_deref(),
            run_id,
            step_index,
            "tool",
            &short_label(stage, 80),
            None,
            None,
        );
    }
}

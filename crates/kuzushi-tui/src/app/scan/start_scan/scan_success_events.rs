use super::*;

impl ShellApp {
    pub(crate) fn apply_scan_finding_stored(
        &mut self,
        fingerprint: String,
        severity: Severity,
        title: String,
    ) {
        if let Some(scan) = &mut self.scan {
            scan.findings_count += 1;
        }
        self.log(
            "finding",
            format!(
                "{} {} {}",
                short_fingerprint(&fingerprint),
                severity.as_str(),
                truncate_ascii(&title, 72)
            ),
        );
    }

    pub(crate) fn apply_scan_finished(&mut self, run_id: String, findings_count: usize) {
        if let Some(scan) = &mut self.scan {
            scan.run_id = Some(run_id.clone());
            scan.stage = "completed".to_string();
            scan.findings_count = findings_count;
            scan.running = false;
            scan.abort_requested = false;
            scan.error = None;
        }
        let target_label = self.scan_target_label();
        append_trace_step(
            self.target.as_deref(),
            &run_id,
            1_000,
            "tool",
            &format!("completed · {findings_count} finding(s)"),
            None,
            None,
        );
        write_run_summary(
            self.target.as_deref(),
            &run_id,
            "complete",
            Some(findings_count as u64),
            &target_label,
        );
        self.refresh_findings(false);
        self.log_scan_alias_hint();
        self.log(
            "scan",
            format!(
                "completed {} with {} finding(s)",
                short_fingerprint(&run_id),
                findings_count
            ),
        );
    }
}

use super::*;
use kuzushi_core::RunTraceStep;

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
        // Mirror the run_id into the Activity session so the dashboard
        // header reflects the worker's actual run id (replacing the
        // "scan-pending" placeholder set by start_scan).
        if let Some(session) = self.activity.as_mut() {
            session.run_id = run_id.clone();
        }
        self.log("scan", format!("run {}", short_fingerprint(&run_id)));
    }

    pub(crate) fn apply_scan_stage(&mut self, stage: String) {
        if let Some(scan) = &mut self.scan {
            scan.stage = stage.clone();
        }
        self.append_scan_stage_trace(&stage);
        self.bridge_scan_stage_to_activity(&stage);
        self.log("scan", stage);
    }

    /// Convert a free-form scan stage string (e.g. "running semgrep",
    /// "persisting 14 finding(s)") into ActivitySession trace step(s) so
    /// the DAG rows reflect scanner progress. Without this bridge, the
    /// Activity view would show every task as Queued for the entire
    /// scan because the scan worker emits ScanEvents on its own channel
    /// rather than RunTraceSteps via the broadcast sink.
    fn bridge_scan_stage_to_activity(&mut self, stage: &str) {
        let Some(session) = self.activity.as_mut() else {
            return;
        };
        // "running <scanner_id>" — emit a `tool` start step under the
        // matching DAG row. The seeded row's task_id is `<id>:scan`,
        // which matches semgrep, codeql, iac-scan, secret-scan; for
        // others (taint-iris:hunt etc.) we fall back to id-only.
        if let Some(scanner_id) = stage.strip_prefix("running ") {
            let scanner_id = scanner_id.trim();
            if scanner_id.is_empty() || scanner_id == "scan" {
                return;
            }
            let task_id = scan_stage_to_task_id(&session.tasks, scanner_id);
            let (module_id, verb) = task_id
                .split_once(':')
                .map(|(m, v)| (m.to_string(), v.to_string()))
                .unwrap_or_else(|| (scanner_id.to_string(), "scan".to_string()));
            session.apply_step(
                RunTraceStep::new(0, "tool", format!("{scanner_id} start"))
                    .with_module_id(module_id)
                    .with_verb(verb),
            );
        } else if let Some(rest) = stage.strip_prefix("persisting ") {
            // Persisting marks the end of all scanner work. Flip every
            // currently-Active row to Done.
            let label = format!("persisting {}", rest.trim());
            for row in session.tasks.values_mut() {
                if matches!(row.state, crate::app::DagTaskState::Active) {
                    row.state = crate::app::DagTaskState::Done;
                    row.completed_at = Some(std::time::Instant::now());
                    row.last_label = label.clone();
                }
            }
        }
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

/// Resolve a bare scanner id (`semgrep`, `codeql`, `iac-scan`,
/// `secret-scan`, `taint-iris`, …) to the seeded DAG row's task_id.
/// The seed uses the producer's qualified tool name (`semgrep:scan`,
/// `taint-iris:hunt`); this lookup picks the row whose module-id
/// prefix matches the scanner id so the bridge can find it without
/// hard-coding mappings.
fn scan_stage_to_task_id(
    tasks: &std::collections::BTreeMap<String, crate::app::DagTaskRow>,
    scanner_id: &str,
) -> String {
    if let Some(exact) = tasks.keys().find(|k| {
        k.split_once(':')
            .map(|(prefix, _)| prefix == scanner_id)
            .unwrap_or(false)
    }) {
        return exact.clone();
    }
    // Fall back to the scanner id verbatim when no seeded row matches
    // (e.g. a scanner the registry doesn't expose as a DAG node).
    format!("{scanner_id}:scan")
}

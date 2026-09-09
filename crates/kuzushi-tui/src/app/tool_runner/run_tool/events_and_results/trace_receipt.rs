use super::*;

pub(super) struct TraceReceiptRefresh {
    target: PathBuf,
    fingerprint: String,
}

pub(super) fn pending_refresh(record: &ToolRunRecordEffect) -> Option<TraceReceiptRefresh> {
    if record.tool_name != "trace:expand" || !tool_run_outcome_has_usable_result(&record.outcome) {
        return None;
    }
    record.run_id.as_ref()?;
    let result = match &record.outcome {
        ToolRunRecordOutcome::Complete { result }
        | ToolRunRecordOutcome::ObservedComplete { result, .. } => result,
        _ => return None,
    };
    Some(TraceReceiptRefresh {
        target: record.target.clone()?,
        fingerprint: result
            .pointer("/data/findingFingerprint")?
            .as_str()?
            .to_string(),
    })
}

impl ShellApp {
    pub(super) fn refresh_recorded_trace_receipt(&mut self, refresh: Option<TraceReceiptRefresh>) {
        let Some(refresh) = refresh else {
            return;
        };
        if self.target() != Some(refresh.target.as_path()) {
            return;
        }
        self.hydrate_trace_expansion_from_store(&refresh.fingerprint);
    }
}

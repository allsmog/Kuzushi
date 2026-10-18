use super::*;
mod summary;
pub(super) use summary::run_receipt_notice;

impl ShellApp {
    pub(super) fn publish_run_focus_receipt(
        &mut self,
        receipt: Option<RunFocusReceipt>,
        answer_acknowledgement: Option<&str>,
    ) {
        let Some(mut receipt) = receipt else {
            return;
        };
        self.enrich_run_focus_receipt(&mut receipt);
        let map_blocker = self.reconcile_durable_phase_outcome(&mut receipt);
        self.tailor_phase_result_destination(&mut receipt);
        apply_map_evidence_blocker(&mut receipt, map_blocker);
        self.persist_phase_attempt(&mut receipt);
        if let Some(session) = self.activity_mut() {
            session.run_focus_receipt = Some(receipt.clone());
        }
        self.publish_receipt_notice(&receipt, answer_acknowledgement);
    }

    fn publish_receipt_notice(&mut self, receipt: &RunFocusReceipt, acknowledgement: Option<&str>) {
        let message = run_receipt_notice(receipt, acknowledgement);
        if self.has_current_run_alert(&receipt.outcome) {
            self.log("run", message);
            return;
        }
        self.set_receipt_outcome_notice(&receipt.outcome, message);
    }

    fn has_current_run_alert(&self, outcome: &str) -> bool {
        let (Some(notice), Some(session)) = (self.advisory().notice.as_ref(), self.activity())
        else {
            return false;
        };
        notice.since >= session.started_at && notice_outweighs_receipt(notice.severity, outcome)
    }

    fn set_receipt_outcome_notice(&mut self, outcome: &str, message: String) {
        match outcome {
            "failed" => self.set_error_notice("run", format!("{message} · /activity for details")),
            "partial" | "blocked" => {
                self.set_warn_notice("run", format!("{message} · /activity for details"));
            }
            _ => self.set_info_notice("run", message),
        }
    }
}

fn notice_outweighs_receipt(severity: NoticeSeverity, outcome: &str) -> bool {
    match severity {
        NoticeSeverity::Error => true,
        NoticeSeverity::Warn => outcome != "failed",
        _ => false,
    }
}

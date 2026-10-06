use kuzushi_core::{allowance::AllowanceSnapshot, capabilities::campaign::StudyPlanReceipt};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct StudyDraftState {
    pub(crate) investigation_id: String,
    pub(crate) campaign_id: Option<String>,
    pub(crate) receipt: Option<StudyPlanReceipt>,
    pub(crate) scan_input: Option<serde_json::Value>,
    pub(crate) allowance: Option<AllowanceSnapshot>,
    pub(crate) accounting_error: Option<String>,
    pub(crate) max_provider_calls: Option<usize>,
    pub(crate) protected_review_calls: Option<usize>,
    pub(crate) max_job_attempts: usize,
}

impl Default for StudyDraftState {
    fn default() -> Self {
        Self {
            investigation_id: kuzushi_core::new_run_id("investigation"),
            campaign_id: None,
            receipt: None,
            scan_input: None,
            allowance: None,
            accounting_error: None,
            max_provider_calls: None,
            protected_review_calls: None,
            max_job_attempts: 1,
        }
    }
}

impl StudyDraftState {
    pub(crate) fn ensure_accounting_ready(&self) -> anyhow::Result<()> {
        if let Some(error) = &self.accounting_error {
            anyhow::bail!("Study continuation unavailable: {error}");
        }
        Ok(())
    }

    pub(crate) fn record_receipt(&mut self, receipt: StudyPlanReceipt) {
        self.scan_input = Some(receipt.scan_input.clone());
        self.receipt = Some(receipt);
    }

    pub(crate) fn approved(&self) -> bool {
        let Some((receipt, allowance)) = self.receipt.as_ref().zip(self.allowance.as_ref()) else {
            return false;
        };
        self.limits_match(allowance)
            && allowance.work_plan.as_ref().is_some_and(|plan| {
                plan.campaign_id == receipt.campaign_id
                    && plan.plan_sha256 == receipt.plan_sha256
                    && plan
                        .jobs
                        .iter()
                        .all(|job| job.max_attempts as usize == self.max_job_attempts)
            })
    }

    fn limits_match(&self, allowance: &AllowanceSnapshot) -> bool {
        self.max_provider_calls == Some(allowance.limits.max_provider_calls as usize)
            && self.protected_review_calls == Some(allowance.limits.protected_review_calls as usize)
    }

    pub(crate) fn next_action(&self) -> &'static str {
        if self.receipt.is_none() {
            return "Prepare study draft";
        }
        if self.approved() {
            return "Open approved jobs";
        }
        "Review plan and allowance"
    }

    /// Changing work replaces the immutable draft, never its investigation.
    pub(crate) fn invalidate_plan(&mut self) {
        self.campaign_id = None;
        self.receipt = None;
    }

    pub(crate) fn restore_allowance(&mut self, allowance: AllowanceSnapshot) {
        self.accounting_error = None;
        self.investigation_id = allowance.investigation_id.clone();
        self.max_provider_calls = Some(allowance.limits.max_provider_calls as usize);
        self.protected_review_calls = Some(allowance.limits.protected_review_calls as usize);
        if let Some(job) = allowance
            .work_plan
            .as_ref()
            .and_then(|plan| plan.jobs.first())
        {
            self.max_job_attempts = job.max_attempts as usize;
        }
        self.allowance = Some(allowance);
    }
}

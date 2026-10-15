use kuzushi_core::{allowance::AllowanceSnapshot, capabilities::campaign::StudyPlanReceipt};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct StudyDraftState {
    pub(crate) brief: Option<kuzushi_core::capabilities::campaign::BriefRevision>,
    pub(crate) investigation_id: String,
    pub(crate) campaign_id: Option<String>,
    pub(crate) receipt: Option<StudyPlanReceipt>,
    pub(crate) review_receipt: Option<kuzushi_core::capabilities::campaign::ReviewStudyReceipt>,
    pub(crate) matrix: super::context_matrix::StudyContextMatrix,
    pub(crate) scope_draft: Option<kuzushi_core::capabilities::campaign::ScopeStudyDraft>,
    pub(crate) scope_receipt: Option<kuzushi_core::capabilities::campaign::ScopeStudyReceipt>,
    pub(crate) scan_input: Option<serde_json::Value>,
    pub(crate) context_baseline_run_id: Option<String>,
    pub(crate) context_experiment:
        Option<kuzushi_core::capabilities::campaign::ContextExperimentReceipt>,
    pub(crate) allowance: Option<AllowanceSnapshot>,
    pub(crate) accounting_error: Option<String>,
    pub(crate) preparation_error: Option<String>,
    pub(crate) baseline_allowance_pending: bool,
    pub(crate) max_provider_calls: Option<usize>,
    pub(crate) protected_review_calls: Option<usize>,
    pub(crate) max_job_attempts: usize,
}

impl Default for StudyDraftState {
    fn default() -> Self {
        Self {
            brief: None,
            investigation_id: kuzushi_core::new_run_id("investigation"),
            campaign_id: None,
            receipt: None,
            review_receipt: None,
            matrix: Default::default(),
            scope_draft: None,
            scope_receipt: None,
            scan_input: None,
            context_baseline_run_id: None,
            context_experiment: None,
            allowance: None,
            accounting_error: None,
            preparation_error: None,
            baseline_allowance_pending: false,
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
        if self.accounting_error.is_some() {
            return false;
        }
        let Some(((id, digest, _), allowance)) = self.plan_identity().zip(self.allowance.as_ref())
        else {
            return false;
        };
        self.limits_match(allowance)
            && allowance.work_plan.as_ref().is_some_and(|plan| {
                plan.campaign_id == id
                    && plan.plan_sha256 == digest
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
        if self.plan_identity().is_none() {
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
        self.review_receipt = None;
        self.matrix.receipt = None;
        self.scope_receipt = None;
        self.context_experiment = None;
    }

    pub(crate) fn restore_allowance(&mut self, allowance: AllowanceSnapshot) {
        self.accounting_error = None;
        self.baseline_allowance_pending = false;
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

impl StudyDraftState {
    pub(crate) fn plan_identity(&self) -> Option<(&str, &str, usize)> {
        if let Some(receipt) = &self.review_receipt {
            return Some((&receipt.campaign_id, &receipt.plan_sha256, 1));
        }
        if let Some(receipt) = &self.scope_receipt {
            return Some((
                &receipt.campaign_id,
                &receipt.plan_sha256,
                receipt.job_count,
            ));
        }
        if let Some(receipt) = &self.matrix.receipt {
            return Some((
                &receipt.campaign_id,
                &receipt.plan_sha256,
                receipt.job_count,
            ));
        }
        self.receipt.as_ref().map(|receipt| {
            (
                receipt.campaign_id.as_str(),
                receipt.plan_sha256.as_str(),
                receipt.job_count,
            )
        })
    }
}

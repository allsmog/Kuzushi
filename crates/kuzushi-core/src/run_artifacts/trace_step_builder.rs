use super::RunTraceStep;

impl RunTraceStep {
    pub fn new(n: usize, kind: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            n,
            kind: kind.into(),
            label: label.into(),
            latency_ms: None,
            cost_usd: None,
            observed_cost_usd: None,
            provider_spend_unresolved: false,
            call_attempted: None,
            module_id: None,
            verb: None,
            parent_step: None,
            severity: None,
            started_at_ms: None,
            model: None,
            provider: None,
            prompt_hash: None,
        }
    }

    pub fn with_latency_ms(mut self, latency_ms: Option<u64>) -> Self {
        self.latency_ms = latency_ms;
        self
    }

    pub fn with_cost_usd(mut self, cost_usd: Option<f64>) -> Self {
        self.cost_usd = cost_usd;
        self.observed_cost_usd = None;
        self.provider_spend_unresolved = false;
        self
    }

    pub fn with_cost_report(mut self, report: crate::runtime::RuntimeCostReport) -> Self {
        self.cost_usd = report.exact_usd();
        self.observed_cost_usd = if report.is_complete() || report.is_unavailable() {
            None
        } else {
            Some(report.observed_usd())
        };
        self.provider_spend_unresolved = self.observed_cost_usd.is_some();
        self
    }

    pub fn with_call_attempted(mut self, attempted: bool) -> Self {
        self.call_attempted = Some(attempted);
        self
    }

    pub fn with_module_id(mut self, module_id: impl Into<String>) -> Self {
        self.module_id = Some(module_id.into());
        self
    }

    pub fn with_verb(mut self, verb: impl Into<String>) -> Self {
        self.verb = Some(verb.into());
        self
    }

    pub fn with_tool_name(mut self, tool_name: &str) -> Self {
        if let Some((module_id, verb)) = tool_name.split_once(':') {
            self.module_id = Some(module_id.to_string());
            self.verb = Some(verb.to_string());
        } else if !tool_name.is_empty() {
            self.module_id = Some(tool_name.to_string());
        }
        self
    }

    pub fn with_parent_step(mut self, parent_step: usize) -> Self {
        self.parent_step = Some(parent_step);
        self
    }

    pub fn with_severity(mut self, severity: impl Into<String>) -> Self {
        self.severity = Some(severity.into());
        self
    }

    pub fn with_started_at_ms(mut self, started_at_ms: u64) -> Self {
        self.started_at_ms = Some(started_at_ms);
        self
    }

    pub fn with_model_metadata(
        mut self,
        model: impl Into<String>,
        provider: impl Into<String>,
        prompt_hash: impl Into<String>,
    ) -> Self {
        self.model = Some(model.into());
        self.provider = Some(provider.into());
        self.prompt_hash = Some(prompt_hash.into());
        self
    }
}

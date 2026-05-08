use super::RunTraceStep;

impl RunTraceStep {
    pub fn new(n: usize, kind: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            n,
            kind: kind.into(),
            label: label.into(),
            latency_ms: None,
            cost_usd: None,
            module_id: None,
            verb: None,
            parent_step: None,
            severity: None,
            started_at_ms: None,
        }
    }

    pub fn with_latency_ms(mut self, latency_ms: Option<u64>) -> Self {
        self.latency_ms = latency_ms;
        self
    }

    pub fn with_cost_usd(mut self, cost_usd: Option<f64>) -> Self {
        self.cost_usd = cost_usd;
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
}

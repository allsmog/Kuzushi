use crate::run_lifecycle::{PersistenceFailureStage, SafeText};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunItemWriterFault {
    pub stage: PersistenceFailureStage,
    pub last_durable_seq: u64,
    pub detail: SafeText,
    pub execution_may_have_occurred: bool,
}

impl RunItemWriterFault {
    pub fn annotate_execution(mut self, execution_may_have_occurred: bool) -> Self {
        self.execution_may_have_occurred |= execution_may_have_occurred;
        if self.execution_may_have_occurred
            && !self.detail.as_str().contains("do not retry automatically")
        {
            self.detail = SafeText::operator_visible(format!(
                "{}; side effects may have occurred; do not retry automatically",
                self.detail
            ));
        }
        self
    }
}

impl std::fmt::Display for RunItemWriterFault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "run-item persistence {:?} failed after sequence {}: {}",
            self.stage, self.last_durable_seq, self.detail
        )
    }
}

impl std::error::Error for RunItemWriterFault {}

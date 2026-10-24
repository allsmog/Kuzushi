#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadState {
    Loading,
    Waiting,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReviewReadFeedback {
    state: ReadState,
    study: bool,
    pub(crate) message: String,
}

impl ReviewReadFeedback {
    pub(crate) fn waiting(study: bool) -> Self {
        Self {
            state: ReadState::Waiting,
            study,
            message: "Work receipts pending · previous results below".into(),
        }
    }
    pub(crate) fn loading(study: bool, filter: Option<&str>) -> Self {
        let message = match (study, filter) {
            (true, _) => "Reading study findings · scope retained".into(),
            (false, Some(filter)) => format!("Reading filter {filter:?} · previous results below"),
            (false, None) => "Reading ledger · previous results below".into(),
        };
        Self {
            state: ReadState::Loading,
            study,
            message,
        }
    }

    pub(crate) fn failed(study: bool) -> Self {
        let message = if study {
            "Study read failed · scope retained"
        } else {
            "Refresh failed · previous results below"
        };
        Self {
            state: ReadState::Failed,
            study,
            message: message.into(),
        }
    }

    pub(crate) fn population_title(&self) -> &'static str {
        match (self.state, self.study) {
            (ReadState::Waiting, _) => "FINDINGS · receipts pending",
            (ReadState::Loading, true) => "FINDINGS · reading study",
            (ReadState::Failed, true) => "FINDINGS · study unavailable",
            (ReadState::Loading, false) => "FINDINGS · previous results",
            (ReadState::Failed, false) => "FINDINGS · read failed",
        }
    }

    pub(crate) fn recovery_lines(&self) -> Vec<&'static str> {
        let mut lines = vec!["Retry: findings refresh"];
        if self.study {
            lines.push("Workspace history: batch clear");
        }
        lines
    }
}

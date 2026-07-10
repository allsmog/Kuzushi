#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AbortReason {
    Operator,
    Budget,
    Watchdog,
}

impl AbortReason {
    pub(crate) fn records_canceled(self) -> bool {
        matches!(self, Self::Operator | Self::Budget)
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Operator => "operator cancel",
            Self::Budget => "budget halt",
            Self::Watchdog => "watchdog timeout",
        }
    }
}

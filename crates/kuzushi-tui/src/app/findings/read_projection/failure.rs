#[derive(Debug, Clone)]
pub(crate) enum FindingsReadFailure {
    ReceiptPending,
    Failed(String),
}

impl From<anyhow::Error> for FindingsReadFailure {
    fn from(error: anyhow::Error) -> Self {
        if error.is::<kuzushi_core::findings::BatchReceiptPending>() {
            return Self::ReceiptPending;
        }
        Self::Failed(format!("{error:#}"))
    }
}

impl From<String> for FindingsReadFailure {
    fn from(error: String) -> Self {
        Self::Failed(error)
    }
}

impl From<&str> for FindingsReadFailure {
    fn from(error: &str) -> Self {
        Self::Failed(error.to_string())
    }
}

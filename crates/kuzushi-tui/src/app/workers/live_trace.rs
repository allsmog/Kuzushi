#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WorkerGeneration(u64);

impl WorkerGeneration {
    pub(crate) fn new(value: u64) -> Self {
        Self(value)
    }

    pub(crate) fn next(value: &mut u64) -> Self {
        *value = value.saturating_add(1);
        Self::new(*value)
    }
}

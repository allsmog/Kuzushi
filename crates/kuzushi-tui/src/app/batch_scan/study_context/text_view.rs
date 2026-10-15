#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum StudyContextTextView {
    #[default]
    Summary,
    Document,
    Scanner,
}

impl StudyContextTextView {
    pub(super) fn toggled(self, requested: Self) -> Self {
        if self == requested {
            Self::Summary
        } else {
            requested
        }
    }
}

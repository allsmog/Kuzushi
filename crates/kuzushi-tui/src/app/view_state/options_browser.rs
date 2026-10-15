use crate::app::FieldEditor;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct OptionsBrowserState {
    pub(crate) selected: Option<String>,
    pub(crate) detail_scroll: usize,
    pub(crate) edit: Option<ToolOptionEdit>,
    pub(crate) notice: Option<String>,
    pub(crate) pending_save: Option<(String, String)>,
    pub(crate) drafts: std::collections::BTreeMap<(String, String), FieldEditor>,
    pub(crate) support_origin: Option<(crate::app::ShellView, crate::app::InputMode)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ToolOptionEdit {
    pub(crate) tool: String,
    pub(crate) option: String,
    pub(crate) field: FieldEditor,
    pub(crate) global: bool,
    pub(crate) error: Option<String>,
    pub(crate) error_scroll: usize,
}

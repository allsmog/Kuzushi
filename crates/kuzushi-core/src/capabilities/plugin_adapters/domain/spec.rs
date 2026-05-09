#[derive(Debug, Clone, Copy)]
pub(crate) struct PluginAdapterSpec<'a> {
    pub(crate) tool_name: &'a str,
    pub(crate) tool_slug: &'static str,
    pub(crate) package_name: &'static str,
    pub(crate) env_var: &'static str,
    pub(crate) install_hint: &'static str,
    pub(crate) prompt_title: &'static str,
    pub(crate) allow_skill_filter: bool,
}

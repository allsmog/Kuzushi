#[derive(Debug, Clone, Copy)]
pub(crate) struct TaintIrisNextCatalogEntry {
    pub(crate) cwe: &'static str,
    pub(crate) name: &'static str,
    pub(crate) taint_class: &'static str,
    pub(crate) languages: &'static [&'static str],
    pub(crate) source_signals: &'static [&'static str],
    pub(crate) sink_signals: &'static [&'static str],
    pub(crate) sanitizer_signals: &'static [&'static str],
    pub(crate) structural_queries: &'static [&'static str],
}

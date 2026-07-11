use super::*;

#[derive(Clone, Copy)]
pub(super) enum PageScrollKind {
    Help,
    Tools,
    History,
    KnowledgeBase,
    Modules,
    Logs,
}

pub(super) fn page_scroll_kind(view: &ShellView, catalog_expanded: bool) -> Option<PageScrollKind> {
    if matches!(view, ShellView::Catalog) {
        return Some(PageScrollKind::Modules);
    }
    let _ = catalog_expanded;
    PAGE_SCROLL_KINDS
        .iter()
        .find_map(|(candidate, kind)| (candidate == view).then_some(*kind))
}

const PAGE_SCROLL_KINDS: &[(ShellView, PageScrollKind)] = &[
    (ShellView::Help, PageScrollKind::Help),
    (ShellView::Quickstart, PageScrollKind::Help),
    (ShellView::Logs, PageScrollKind::Logs),
    (ShellView::Tools, PageScrollKind::Tools),
    (ShellView::History, PageScrollKind::History),
    (ShellView::KnowledgeBase, PageScrollKind::KnowledgeBase),
];

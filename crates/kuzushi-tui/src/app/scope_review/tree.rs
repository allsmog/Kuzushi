//! Bounded, inventory-backed navigation. Expanding a branch never starts work.
use super::*;
use kuzushi_core::workspace::ScopeFileFilter;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const SCOPE_TREE_PAGE_SIZE: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ScopeBranch {
    Scope(String),
    Uncovered,
    Excluded,
    Overlap,
}

impl ScopeBranch {
    pub(crate) fn filter(&self) -> ScopeFileFilter {
        match self {
            Self::Scope(id) => ScopeFileFilter::Scope {
                scope_id: id.clone(),
            },
            Self::Uncovered => ScopeFileFilter::Uncovered,
            Self::Excluded => ScopeFileFilter::Excluded,
            Self::Overlap => ScopeFileFilter::Overlap,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ScopeTreeRow {
    Branch(ScopeBranch),
    File { branch: ScopeBranch, path: String },
    Page { branch: ScopeBranch, offset: usize },
}

impl ScopeTreeRow {
    pub(crate) fn branch(&self) -> &ScopeBranch {
        match self {
            Self::Branch(branch) | Self::File { branch, .. } | Self::Page { branch, .. } => branch,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct ScopeTreeState {
    pub expanded: BTreeSet<ScopeBranch>,
    pub pages: BTreeMap<ScopeBranch, ScopeFilePage>,
}

impl ScopeReviewState {
    pub(crate) fn tree_rows(&self) -> Vec<ScopeTreeRow> {
        let mut rows = Vec::new();
        for branch in self.tree_branches() {
            rows.push(ScopeTreeRow::Branch(branch.clone()));
            if self.tree.expanded.contains(&branch) {
                append_members(&mut rows, &branch, &self.tree_page(&branch));
            }
        }
        rows
    }

    pub(crate) fn selected_row(&self) -> Option<ScopeTreeRow> {
        self.tree_rows().into_iter().nth(self.cursor)
    }

    pub(crate) fn selected_file(&self) -> Option<String> {
        match self.selected_row()? {
            ScopeTreeRow::File { path, .. } => Some(path),
            _ => None,
        }
    }

    pub(crate) fn tree_branches(&self) -> Vec<ScopeBranch> {
        let Some(review) = &self.review else {
            return Vec::new();
        };
        scope_ids(review)
            .map(|id| ScopeBranch::Scope(id.into()))
            .chain([
                ScopeBranch::Uncovered,
                ScopeBranch::Excluded,
                ScopeBranch::Overlap,
            ])
            .collect()
    }

    pub(crate) fn tree_page(&self, branch: &ScopeBranch) -> ScopeFilePage {
        if let Some(page) = self.tree.pages.get(branch) {
            return page.clone();
        }
        let Some(review) = &self.review else {
            return empty_page();
        };
        preview_page(review, branch)
    }

    pub(super) fn restore_tree_selection(&mut self, selected: Option<ScopeTreeRow>) {
        let rows = self.tree_rows();
        self.cursor = selected
            .as_ref()
            .and_then(|row| {
                rows.iter().position(|next| next == row).or_else(|| {
                    rows.iter()
                        .position(|next| next == &ScopeTreeRow::Branch(row.branch().clone()))
                })
            })
            .unwrap_or(0);
    }
}

fn append_members(rows: &mut Vec<ScopeTreeRow>, branch: &ScopeBranch, page: &ScopeFilePage) {
    if page.offset > 0 {
        rows.push(ScopeTreeRow::Page {
            branch: branch.clone(),
            offset: page.offset.saturating_sub(SCOPE_TREE_PAGE_SIZE),
        });
    }
    rows.extend(
        page.files
            .iter()
            .take(SCOPE_TREE_PAGE_SIZE)
            .map(|path| ScopeTreeRow::File {
                branch: branch.clone(),
                path: path.clone(),
            }),
    );
    if page.offset + page.files.len() < page.total {
        rows.push(ScopeTreeRow::Page {
            branch: branch.clone(),
            offset: page.offset + SCOPE_TREE_PAGE_SIZE,
        });
    }
}

fn preview_page(review: &ScanScopeReview, branch: &ScopeBranch) -> ScopeFilePage {
    let coverage = &review.coverage;
    let preview = match branch {
        ScopeBranch::Scope(id) => coverage
            .discovery_members
            .get(id)
            .or_else(|| coverage.context_members.get(id)),
        ScopeBranch::Uncovered => Some(&coverage.uncovered_files),
        ScopeBranch::Excluded => Some(&coverage.excluded_files),
        ScopeBranch::Overlap => return overlap_page(review),
    };
    preview.map_or_else(empty_page, |files| ScopeFilePage {
        offset: 0,
        total: files.total,
        files: files
            .files
            .iter()
            .take(SCOPE_TREE_PAGE_SIZE)
            .cloned()
            .collect(),
    })
}

fn overlap_page(review: &ScanScopeReview) -> ScopeFilePage {
    ScopeFilePage {
        offset: 0,
        total: review.coverage.overlaps.total,
        files: review
            .coverage
            .overlaps
            .files
            .keys()
            .take(SCOPE_TREE_PAGE_SIZE)
            .cloned()
            .collect(),
    }
}

fn empty_page() -> ScopeFilePage {
    ScopeFilePage {
        offset: 0,
        total: 0,
        files: Vec::new(),
    }
}

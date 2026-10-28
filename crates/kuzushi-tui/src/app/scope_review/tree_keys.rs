use super::*;
use crossterm::event::KeyCode;

impl ShellApp {
    pub(super) fn scope_tree_key(&mut self, code: KeyCode) -> Option<InputUpdate> {
        if self.scope_review()?.files.is_some() {
            return None;
        }
        let selected = self.scope_review()?.selected_row()?;
        match (code, selected) {
            (KeyCode::Right, row @ ScopeTreeRow::Branch(_)) => self.expand_scope_branch(row),
            (KeyCode::Left, row) => self.collapse_scope_branch(row),
            (KeyCode::Enter, ScopeTreeRow::Page { branch, offset }) => {
                return Some(self.request_tree_page(branch, offset))
            }
            (KeyCode::Enter, ScopeTreeRow::File { branch, .. }) => {
                self.open_scope_file_actions(branch)
            }
            _ => return None,
        }
        Some(InputUpdate::handled())
    }

    fn expand_scope_branch(&mut self, row: ScopeTreeRow) {
        let branch = row.branch().clone();
        let state = self.router.scope_review_mut().as_mut().unwrap();
        if state.tree_page(&branch).total == 0 {
            state.notice = Some("This branch has no recorded files.".into());
            return;
        }
        if !state.tree.expanded.insert(branch) {
            state.cursor = (state.cursor + 1).min(state.row_count().saturating_sub(1));
        }
        state.scroll = 0;
        state.detail_reader.scroll = 0;
        state.notice = None;
    }

    fn collapse_scope_branch(&mut self, row: ScopeTreeRow) {
        let state = self.router.scope_review_mut().as_mut().unwrap();
        let branch = row.branch().clone();
        if matches!(row, ScopeTreeRow::Branch(_)) {
            state.tree.expanded.remove(&branch);
        }
        state.restore_tree_selection(Some(ScopeTreeRow::Branch(branch)));
        state.scroll = 0;
        state.detail_reader.scroll = 0;
        state.notice = None;
    }

    fn open_scope_file_actions(&mut self, branch: ScopeBranch) {
        let state = self.router.scope_review_mut().as_mut().unwrap();
        state.menu = Some(if branch == ScopeBranch::Excluded {
            11
        } else {
            4
        });
        state.scroll = 0;
        state.notice = None;
    }

    fn request_tree_page(&mut self, branch: ScopeBranch, offset: usize) -> InputUpdate {
        let reference = self
            .scope_review()
            .unwrap()
            .review
            .as_ref()
            .unwrap()
            .reference
            .clone();
        let update = self
            .dispatch_scope_request(json!({"operation":"files", "proposalRef":reference,
            "fileFilter":branch.filter(), "offset":offset, "pageSize":SCOPE_TREE_PAGE_SIZE}));
        if let Some(request) = self
            .router
            .scope_review_mut()
            .as_mut()
            .unwrap()
            .pending
            .as_mut()
        {
            request.tree_branch = Some(branch);
        }
        update
    }
}

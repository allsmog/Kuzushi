use super::*;
use kuzushi_core::findings::{FindingGroupsPage, FindingGroupsRequest};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FindingGroupsRouteState {
    pub(crate) target: Option<PathBuf>,
    pub(crate) request: FindingGroupsRequest,
    pub(crate) cursor: usize,
    pub(crate) list_origin: Option<(FindingGroupsRequest, usize, u16)>,
    pub(crate) return_scroll: u16,
    pub(crate) return_to_groups: bool,
}
impl Default for FindingGroupsRouteState {
    fn default() -> Self {
        Self {
            target: None,
            request: FindingGroupsRequest::first_page(),
            cursor: 0,
            list_origin: None,
            return_scroll: 0,
            return_to_groups: false,
        }
    }
}

impl ShellApp {
    pub(crate) fn open_finding_groups(&mut self) {
        let state = &self.router.relationships.groups;
        if state.target != self.target_owned() || !state.return_to_groups {
            self.router.relationships.groups = FindingGroupsRouteState {
                target: self.target_owned(),
                request: FindingGroupsRequest {
                    filter: self.active_findings_filter().clone(),
                    run_ids: self.selected_current_scan_run_refs().unwrap_or_default(),
                    ..FindingGroupsRequest::first_page()
                },
                ..Default::default()
            };
        }
        self.router.relationships.show_groups = true;
        self.router.relationships.note = None;
        self.set_shell_view(ShellView::Relationships);
        let scroll = self.router.relationships.groups.return_scroll;
        self.router.default_scroll_mut().set(scroll);
        if self.input().is_empty() {
            self.set_input_mode(InputMode::Navigate);
        }
    }

    pub(crate) fn finding_groups_page(&self) -> ViewDataState<Result<FindingGroupsPage, String>> {
        let key = ViewHydrationKey::FindingGroups(self.router.relationships.groups.request.clone());
        self.workbench_cache()
            .borrow()
            .cached_finding_groups(self.target(), &key)
    }

    pub(crate) fn handle_group_key(
        &mut self,
        key: KeyEvent,
    ) -> Option<state_transitions::InputUpdate> {
        if self.input_mode() != InputMode::Navigate {
            return None;
        }
        if !key.modifiers.difference(KeyModifiers::SHIFT).is_empty() {
            return None;
        }
        self.apply_group_key(key.code)
            .then(state_transitions::InputUpdate::handled)
    }

    fn apply_group_key(&mut self, key: KeyCode) -> bool {
        match key {
            KeyCode::Char('j') | KeyCode::Down => self.move_group_cursor(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_group_cursor(-1),
            KeyCode::Enter => self.open_group_selection(),
            KeyCode::Esc => self.close_group_members(),
            KeyCode::Char('n') => self.page_groups(true),
            KeyCode::Char('p') => self.page_groups(false),
            KeyCode::Char('R') => self.refresh_finding_groups(),
            KeyCode::Tab | KeyCode::Char('L') => self.show_group_relationships(),
            _ => return false,
        }
        true
    }

    fn move_group_cursor(&mut self, delta: isize) {
        let ViewDataState::Ready(Ok(page)) = self.finding_groups_page() else {
            return;
        };
        let count = page.groups.len() + page.members.len();
        let route = &mut self.router.relationships.groups;
        route.cursor = route
            .cursor
            .saturating_add_signed(delta)
            .min(count.saturating_sub(1));
        self.router.default_scroll_mut().set(0);
    }

    fn open_group_selection(&mut self) {
        let ViewDataState::Ready(Ok(page)) = self.finding_groups_page() else {
            return;
        };
        let cursor = self.router.relationships.groups.cursor;
        if let Some(member) = page.members.get(cursor) {
            self.router.relationships.groups.return_to_groups = true;
            self.router.relationships.groups.return_scroll = self.router.default_scroll().offset();
            let effects = self.open_finding_effects(&format!("generation:{}", member.finding_id));
            EffectRuntime::execute(self, effects);
            return;
        }
        let Some(group) = page.groups.get(cursor) else {
            return;
        };
        let scroll = self.router.default_scroll().offset();
        let route = &mut self.router.relationships.groups;
        route.list_origin = Some((route.request.clone(), cursor, scroll));
        route.request.group_id = Some(group.id.clone());
        route.request.expected_revision = Some(page.revision.clone());
        route.request.offset = 0;
        route.cursor = 0;
        self.router.default_scroll_mut().set(0);
    }

    fn close_group_members(&mut self) {
        let route = &mut self.router.relationships.groups;
        if let Some((request, cursor, scroll)) = route.list_origin.take() {
            route.request = request;
            route.cursor = cursor;
            self.router.default_scroll_mut().set(scroll);
            return;
        }
        self.go_back();
    }

    fn page_groups(&mut self, next: bool) {
        let ViewDataState::Ready(Ok(page)) = self.finding_groups_page() else {
            return;
        };
        if next && !page.has_more {
            return;
        }
        let route = &mut self.router.relationships.groups;
        route.request.expected_revision = Some(page.revision.clone());
        route.request.offset = if next {
            route.request.offset + route.request.limit
        } else {
            route.request.offset.saturating_sub(route.request.limit)
        };
        route.cursor = 0;
        self.router.default_scroll_mut().set(0);
    }

    pub(crate) fn refresh_finding_groups(&mut self) {
        let route = &mut self.router.relationships.groups;
        route.request.group_id = None;
        route.request.expected_revision = None;
        route.request.offset = 0;
        route.cursor = 0;
        route.list_origin = None;
        route.return_scroll = 0;
        self.router.default_scroll_mut().set(0);
        self.workbench_cache().borrow_mut().group_pages.clear();
    }

    fn show_group_relationships(&mut self) {
        let ViewDataState::Ready(Ok(page)) = self.finding_groups_page() else {
            return;
        };
        let cursor = self.router.relationships.groups.cursor;
        let id = page
            .members
            .get(cursor)
            .map(|member| member.finding_id)
            .or_else(|| {
                page.groups
                    .get(cursor)
                    .map(|group| group.representative.finding_id)
            });
        self.router.relationships.finding_id = id;
        self.router.relationships.offset = 0;
        self.router.relationships.cursor = 0;
        self.router.relationships.show_groups = false;
        self.router.relationships.groups.return_to_groups = true;
        self.router.default_scroll_mut().set(0);
    }
}

#[cfg(test)]
mod tests;

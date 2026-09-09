use super::*;

impl ShellApp {
    pub(crate) fn open_map_scope_picker(&mut self) -> Result<()> {
        let tree = self.cached_map_scope_tree();
        let leaves = tree.as_ref().map(eligible_leaf_scopes).unwrap_or_default();
        let mut choices = vec![
            (None, "Whole repository · one build".into()),
            (
                Some(ALL_LEAF_SCOPES.into()),
                format!("All eligible scopes · {} builds", leaves.len()),
            ),
        ];
        choices.extend(
            leaves
                .iter()
                .map(|scope| (Some(format!("id:{}", scope.id)), scope.rel_path.clone())),
        );
        let selected = self.map_option_string("scope");
        self.router
            .setup_mut()
            .map_run_config_mut()
            .begin_scope(choices, selected.as_deref());
        Ok(())
    }

    pub(crate) fn select_map_scope(&mut self) -> Result<()> {
        let choice = self
            .router
            .setup()
            .map_run_config()
            .scope()
            .and_then(|picker| picker.selected())
            .context("No matching scope; change the search or Esc to cancel")?
            .clone();
        let tree = self.cached_map_scope_tree();
        let leaves = tree.as_ref().map(eligible_leaf_scopes).unwrap_or_default();
        self.refresh_all_scopes_label(leaves.len());
        validate_selected_scope(choice.value.as_deref(), &leaves)?;
        if !self.confirm_map_scope_selection(
            choice.value.as_deref(),
            tree.as_ref(),
            leaves.len(),
        )? {
            return Ok(());
        }
        self.apply_map_scope_choice(choice.value.clone(), tree.as_ref(), leaves.len())?;
        if choice.value.as_deref() == Some(ALL_LEAF_SCOPES) {
            let key = tree
                .as_ref()
                .map(|tree| self.all_scope_review_key(tree))
                .transpose()?;
            self.router
                .setup_mut()
                .map_run_config_mut()
                .set_all_scopes_reviewed(key);
        }
        self.router.setup_mut().map_run_config_mut().finish_scope();
        Ok(())
    }

    fn refresh_all_scopes_label(&mut self, count: usize) {
        if let Some(picker) = self.router.setup_mut().map_run_config_mut().scope_mut() {
            picker.refresh_label(
                ALL_LEAF_SCOPES,
                format!("All eligible scopes · {count} builds"),
            );
        }
    }

    fn confirm_map_scope_selection(
        &mut self,
        value: Option<&str>,
        tree: Option<&kuzushi_core::NestedProjectScopeTree>,
        count: usize,
    ) -> Result<bool> {
        if value != Some(ALL_LEAF_SCOPES) || count <= ALL_SCOPES_REVIEW_THRESHOLD {
            return Ok(true);
        }
        let key = self.all_scope_review_key(tree.context("scope tree is unavailable")?)?;
        let cost = self.map_cost_upper_bound(count);
        let state = self.router.setup_mut().map_run_config_mut();
        let picker = state.scope_mut().context("scope picker is not open")?;
        if picker.pending_review.as_deref() == Some(&key) {
            return Ok(true);
        }
        picker.pending_review = Some(key);
        // Review stays inside the selector, so Escape leaves the saved plan untouched.
        state.set_error(format!("Review {count} builds · {cost}. Above the {ALL_SCOPES_REVIEW_THRESHOLD}-scope threshold. Enter again to select; Esc cancels."));
        Ok(false)
    }
}

fn validate_selected_scope(value: Option<&str>, leaves: &[&NestedProjectScope]) -> Result<()> {
    match value {
        Some(ALL_LEAF_SCOPES) => validate_all_scope_count(leaves.len()),
        Some(value) => {
            anyhow::ensure!(
                leaves
                    .iter()
                    .any(|scope| value == format!("id:{}", scope.id)),
                "This scope is no longer eligible; reopen the scope selector"
            );
            Ok(())
        }
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests;
